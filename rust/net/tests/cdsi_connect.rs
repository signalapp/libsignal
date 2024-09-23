//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::Duration;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use libsignal_net::auth::Auth;
use libsignal_net::cdsi::CdsiConnection;
use libsignal_net::enclave::EnclaveEndpointConnection;
use libsignal_net::env::STAGING;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::tcp_ssl::DirectConnector;
use libsignal_net::infra::utils::ObservableEvent;
use rand_core::{OsRng, RngCore};

#[tokio::test]
async fn can_connect_to_cdsi_staging() {
    init_logger();

    let mut rng = OsRng;

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

    let network_changed = ObservableEvent::default();
    let endpoint_connection =
        EnclaveEndpointConnection::new(&STAGING.cdsi, Duration::from_secs(10), &network_changed);
    let auth = Auth::from_uid_and_secret(uid, secret);

    let transport = {
        let dns = DnsResolver::new(&network_changed);
        DirectConnector::new(dns)
    };
    CdsiConnection::connect(&endpoint_connection, transport, auth)
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
