//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::Arc;

use anyhow::anyhow;
use clap::{Parser, ValueEnum};
use either::Either;
use libsignal_net::certs::SIGNAL_ROOT_CERTIFICATES;
use libsignal_net::chat::test_support::simple_chat_connection;
use libsignal_net::connect_state::{ConnectState, ConnectionResources, SUGGESTED_CONNECT_CONFIG};
use libsignal_net::infra::EnableDomainFronting;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::host::Host;
use libsignal_net::infra::http_client::{Http2Client, Http2Connector};
use libsignal_net::infra::route::provider::EmptyProvider;
use libsignal_net::infra::route::{
    ConnectError, DirectOrProxyMode, DirectOrProxyProvider, DirectTcpRouteProvider, HttpVersion,
    HttpsProvider, TlsRouteProvider,
};
use libsignal_net::infra::timeouts::TimeoutOr;
use libsignal_net::infra::utils::no_network_change_events;
use libsignal_net_chat::api::Unauth;
use libsignal_net_chat::api::usernames::UnauthenticatedChatApi;
use nonzero_ext::nonzero;
use static_assertions::assert_impl_all;

#[derive(Parser)]
struct Config {
    env: Environment,
    username: String,

    #[arg(long)]
    use_grpc: bool,
    #[arg(long, requires = "use_grpc", default_value = "")]
    host: String,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Environment {
    Staging,
    #[value(alias("prod"))]
    Production,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::new()
        .filter_module(module_path!(), log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let Config {
        env,
        username,
        use_grpc,
        host,
    } = Config::parse();
    let env = match env {
        Environment::Staging => libsignal_net::env::STAGING,
        Environment::Production => libsignal_net::env::PROD,
    };

    let chat_connection = if use_grpc {
        let host = if host.is_empty() {
            env.chat_domain_config.connect.hostname
        } else {
            &host
        };
        Either::Left(Unauth(grpc_connection(host).await?))
    } else {
        Either::Right(Unauth(
            simple_chat_connection(
                &env,
                EnableDomainFronting::AllDomains,
                DirectOrProxyMode::DirectOnly,
                |_route| true,
            )
            .await?,
        ))
    };

    let username = usernames::Username::new(&username)?;
    if let Some(aci) = chat_connection
        .look_up_username_hash(&username.hash())
        .await?
    {
        log::info!("found {}", aci.service_id_string());
    } else {
        log::info!("no user found");
    }

    Ok(())
}

assert_impl_all!(Http2Client<tonic::body::Body>: tonic::client::GrpcService<tonic::body::Body>);

/// Connect to a gRPC server that uses Signal's pinned root certificate.
///
/// Eventually this should be covered by a libsignal-net-level API like `simple_chat_connection`.
/// We're not just making an *arbitrary* H2 connection; we're specifically talking to chat-server.
async fn grpc_connection(host: &str) -> anyhow::Result<Http2Client<tonic::body::Body>> {
    let host: Arc<str> = Arc::from(host);
    let connect_state = Arc::new(ConnectState::new(SUGGESTED_CONNECT_CONFIG));
    let resolver = DnsResolver::new(&no_network_change_events());
    let (client, _route_info) = ConnectionResources {
        connect_state: &connect_state,
        dns_resolver: &resolver,
        network_change_event: &no_network_change_events(),
        confirmation_header_name: None,
    }
    .connect_h2(
        HttpsProvider::new(
            host.clone(),
            HttpVersion::Http2,
            EmptyProvider::default(),
            TlsRouteProvider::new(
                SIGNAL_ROOT_CERTIFICATES,
                None,
                Host::Domain(host.clone()),
                DirectOrProxyProvider::direct(DirectTcpRouteProvider::new(
                    host.clone(),
                    nonzero!(443u16),
                )),
            ),
        ),
        Http2Connector::new(),
        "grpc",
    )
    .await
    .map_err(|e| match e {
        TimeoutOr::Timeout { .. } => anyhow!("timed out"),
        TimeoutOr::Other(ConnectError::NoResolvedRoutes) => anyhow!("no resolved routes"),
        TimeoutOr::Other(ConnectError::AllAttemptsFailed) => anyhow!("all attempts failed"),
        TimeoutOr::Other(ConnectError::FatalConnect(e)) => e.into(),
    })?;
    Ok(client)
}
