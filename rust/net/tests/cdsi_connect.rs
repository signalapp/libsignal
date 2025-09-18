//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use base64::prelude::{BASE64_STANDARD, Engine as _};
use http::HeaderName;
use libsignal_net::auth::Auth;
use libsignal_net::cdsi::CdsiConnection;
use libsignal_net::connect_state::{ConnectState, ConnectionResources, SUGGESTED_CONNECT_CONFIG};
use libsignal_net::env::STAGING;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::utils::no_network_change_events;
use libsignal_net_infra::EnableDomainFronting;
use libsignal_net_infra::route::DirectOrProxyProvider;
use rand_core::{OsRng, RngCore, TryRngCore as _};

#[tokio::test]
async fn can_connect_to_cdsi_staging() {
    init_logger();

    let mut rng = OsRng.unwrap_err();

    let uid = {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes[..]);
        bytes
    };

    let Some(secret) = get_enclave_secret() else {
        println!(
            "LIBSIGNAL_TESTING_CDSI_ENCLAVE_SECRET environment variable is not set. The test will be ignored."
        );
        return;
    };

    let auth = Auth::from_uid_and_secret(uid, secret);
    let network_changed = no_network_change_events();
    let resolver = DnsResolver::new(&network_changed);
    let cdsi_env = STAGING.cdsi;

    let confirmation_header_name = cdsi_env
        .domain_config
        .connect
        .confirmation_header_name
        .map(HeaderName::from_static);
    let connect_state = ConnectState::new(SUGGESTED_CONNECT_CONFIG);
    let connection_resources = ConnectionResources {
        connect_state: &connect_state,
        dns_resolver: &resolver,
        network_change_event: &network_changed,
        confirmation_header_name,
    };

    CdsiConnection::connect_with(
        connection_resources,
        DirectOrProxyProvider::direct(
            cdsi_env.enclave_websocket_provider(EnableDomainFronting::No),
        ),
        cdsi_env.ws_config,
        &cdsi_env.params,
        &auth,
    )
    .await
    .expect("can connect to cdsi");
}

fn parse_auth_secret<const N: usize>(b64: &str) -> [u8; N] {
    BASE64_STANDARD
        .decode(b64)
        .expect("valid b64")
        .try_into()
        .expect("secret is the right bytes")
}

fn init_logger() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn get_enclave_secret() -> Option<[u8; 32]> {
    std::env::var("LIBSIGNAL_TESTING_CDSI_ENCLAVE_SECRET")
        .map(|b64| parse_auth_secret(&b64))
        .ok()
}
