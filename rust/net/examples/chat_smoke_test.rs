//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::Duration;

use clap::{Args, Parser, ValueEnum};
use http::uri::PathAndQuery;
use libsignal_net::chat::{chat_service, ChatServiceError};
use libsignal_net::env::constants::WEB_SOCKET_PATH;
use libsignal_net::env::Svr3Env;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::tcp_ssl::DirectConnector;
use libsignal_net::infra::{make_ws_config, ConnectionParams, EndpointConnection, RouteType};
use tokio::sync::mpsc;

#[derive(Parser)]
struct Config {
    #[clap(flatten)]
    route: Option<Route>,
    env: Environment,
    #[arg(long)]
    try_all_routes: bool,
}

#[derive(Args)]
#[group(multiple = false)]
struct Route {
    #[arg(long)]
    proxy_g: bool,
    #[arg(long)]
    proxy_f: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Environment {
    Staging,
    #[value(alias("prod"))]
    Production,
}

#[tokio::main]
async fn main() {
    env_logger::builder()
        .filter_module(module_path!(), log::LevelFilter::Info)
        .parse_default_env()
        .init();

    let config = Config::parse();
    let env = match config.env {
        Environment::Staging => libsignal_net::env::STAGING,
        Environment::Production => libsignal_net::env::PROD,
    };

    let mut connection_params = env.chat_domain_config.connection_params_with_fallback();
    match config.route {
        Some(Route { proxy_g: true, .. }) => {
            connection_params.retain(|c| c.route_type == RouteType::ProxyG)
        }
        Some(Route { proxy_f: true, .. }) => {
            connection_params.retain(|c| c.route_type == RouteType::ProxyF)
        }
        _ if config.try_all_routes => {
            // Retain every route, including the direct one.
        }
        _ => connection_params.retain(|c| c.route_type == RouteType::Direct),
    };

    if config.try_all_routes {
        for route in connection_params {
            log::info!("trying {} ({})", route.sni, route.route_type);
            test_connection(&env, vec![route])
                .await
                .unwrap_or_else(|e| log::error!("failed to connect: {e}"));
        }
    } else {
        test_connection(&env, connection_params)
            .await
            .unwrap_or_else(|e| log::error!("failed to connect: {e}"));
    }
}

async fn test_connection(
    env: &libsignal_net::env::Env<'static, Svr3Env<'static>>,
    connection_params: Vec<ConnectionParams>,
) -> Result<(), ChatServiceError> {
    let dns_resolver = DnsResolver::new_with_static_fallback(env.static_fallback());
    let transport_connector = DirectConnector::new(dns_resolver);
    let chat_endpoint = PathAndQuery::from_static(WEB_SOCKET_PATH);
    let chat_ws_config = make_ws_config(chat_endpoint, Duration::from_secs(5));
    let connection =
        EndpointConnection::new_multi(connection_params, Duration::from_secs(5), chat_ws_config);

    let (incoming_tx, _incoming_rx) = mpsc::channel(1);
    let chat = chat_service(
        &connection,
        transport_connector,
        incoming_tx,
        "".to_owned(),
        "".to_owned(),
    );

    chat.connect_unauthenticated().await?;
    chat.disconnect().await;
    log::info!("completed successfully");
    Ok(())
}
