//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net::auth::Auth;
use libsignal_net::enclave::MrEnclave;
use libsignal_net::env::STAGING;
use libsignal_net::infra::utils::no_network_change_events;
use libsignal_net::svr2::Error;
use libsignal_net::svrb::direct::direct_connect;

/// Connecting to an enclave that doesn't exist should turn an HTTP 404 into an
/// error of a very certain shape, which [`Error::is_enclave_not_found`]
/// recognizes so callers can skip a decommissioned enclave.
/// This test verifies error shape assumption.
#[tokio::test]
async fn connecting_to_missing_enclave_is_enclave_not_found() {
    if std::env::var("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS").is_err() {
        println!("SKIPPED: running integration tests is not enabled");
        return;
    }

    // Server 404s before it looks at the credentials, so anything would do.
    let auth = Auth {
        username: "test-username".to_string(),
        password: "test-password".to_string(),
    };

    let network_changed = no_network_change_events();

    let svr2_env = {
        let mut env = STAGING.svr2.current;
        env.params.mr_enclave = MrEnclave::new(&[0; 32]);
        env
    };

    let result = direct_connect(&svr2_env, &auth, &network_changed)
        .await
        .map_err(Error::from_enclave_error);

    let error = result
        .err()
        .expect("connecting to a nonexistent enclave must not succeed");

    assert!(
        error.is_enclave_not_found(),
        "expected an enclave-not-found (404) error, got: {error:?}"
    );
}
