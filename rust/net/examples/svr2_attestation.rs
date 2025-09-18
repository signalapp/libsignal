//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! An example tool that allows to extract attestation message from enclaves.
//!
//! IMPORTANT: It outputs binary data, so make sure to pipe the output properly.
//!
//! Usage: `./svr2_attestation --username USERNAME --password PASSWORD | xxd`

use std::io::Write;

use attest::enclave;
use attest::enclave::Handshake;
use clap::Parser as _;
use http::HeaderName;
use http::uri::PathAndQuery;
use libsignal_net::auth::Auth;
use libsignal_net::connect_state::{ConnectState, ConnectionResources, SUGGESTED_CONNECT_CONFIG};
use libsignal_net::enclave::{EnclaveKind, EndpointParams, MrEnclave, NewHandshake, SvrSgx};
use libsignal_net::svr::SvrConnection;
use libsignal_net_infra::EnableDomainFronting;
use libsignal_net_infra::dns::DnsResolver;
use libsignal_net_infra::route::DirectOrProxyProvider;
use libsignal_net_infra::utils::no_network_change_events;

#[derive(clap::Parser)]
struct Args {
    #[arg(long, env = "USERNAME")]
    username: String,
    #[arg(long, env = "PASSWORD")]
    password: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Make requests to prod environment"
    )]
    prod: bool,
}

struct LoggingNewHandshake<E: EnclaveKind>(E);

impl<E: EnclaveKind> EnclaveKind for LoggingNewHandshake<E> {
    type RaftConfigType = E::RaftConfigType;

    fn url_path(enclave: &[u8]) -> PathAndQuery {
        E::url_path(enclave)
    }
}

fn cast_params<'a, T, U>(params: &'a EndpointParams<'a, T>) -> EndpointParams<'a, U>
where
    T: EnclaveKind<RaftConfigType = U::RaftConfigType>,
    U: EnclaveKind,
{
    EndpointParams {
        mr_enclave: MrEnclave::new(params.mr_enclave.as_ref()),
        raft_config: params.raft_config.clone(),
    }
}

impl<E: NewHandshake + 'static> NewHandshake for LoggingNewHandshake<E> {
    fn new_handshake(
        params: &EndpointParams<Self>,
        attestation_message: &[u8],
    ) -> enclave::Result<Handshake> {
        std::io::stdout()
            .write_all(attestation_message)
            .expect("can write to stdout");
        E::new_handshake(&cast_params(params), attestation_message)
    }
}

#[tokio::main]
async fn main() {
    let Args {
        username,
        password,
        prod,
    } = Args::parse();

    let auth = Auth { username, password };

    let env = if prod {
        libsignal_net::env::PROD.svr2
    } else {
        libsignal_net::env::STAGING.svr2
    };

    let resolver = DnsResolver::new(&no_network_change_events());

    let confirmation_header_name = env
        .domain_config
        .connect
        .confirmation_header_name
        .map(HeaderName::from_static);
    let connect_state = ConnectState::new(SUGGESTED_CONNECT_CONFIG);
    let connection_resources = ConnectionResources {
        connect_state: &connect_state,
        dns_resolver: &resolver,
        network_change_event: &no_network_change_events(),
        confirmation_header_name,
    };

    let params: EndpointParams<'_, LoggingNewHandshake<SvrSgx>> = cast_params(&env.params);

    let _connection = SvrConnection::connect(
        connection_resources,
        DirectOrProxyProvider::direct(env.enclave_websocket_provider(EnableDomainFronting::No)),
        env.ws_config,
        &params,
        &auth,
    )
    .await
    .expect("can connect");
}
