//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
//! An integration test validating the availability and proper functioning of a
//! built-in Svr3Env pointing at the staging deployment.
//!
//! A valid auth secret value used to authenticate to the enclave needs to be
//! provided in LIBSIGNAL_TESTING_ENCLAVE_SECRET environment variable.

use assert_matches::assert_matches;
use async_trait::async_trait;
use base64::prelude::{Engine, BASE64_STANDARD};
use colored::Colorize as _;
use libsignal_net::auth::Auth;
use libsignal_net::enclave::PpssSetup;
use libsignal_net::env::Svr3Env;
use libsignal_net::svr3::traits::*;
use libsignal_net::svr3::{Error, OpaqueMaskedShareSet};
use nonzero_ext::nonzero;
use rand_core::{CryptoRngCore, OsRng, RngCore};

const PASSWORD: &str = "pA$$w0Rd";

struct Svr3Client {
    env: Svr3Env<'static>,
    auth: Auth,
}

#[async_trait]
impl Svr3Connect for Svr3Client {
    type Env = Svr3Env<'static>;

    async fn connect(&self) -> <Svr3Env as PpssSetup>::ConnectionResults {
        self.env.connect_directly(&self.auth).await
    }
}

#[tokio::test]
async fn svr3_integration() {
    init_logger();

    let Some(enclave_secret) = get_enclave_secret() else {
        println!(
            "LIBSIGNAL_TESTING_ENCLAVE_SECRET environment variable is not set. The test will be ignored."
        );
        return;
    };

    let mut rng = OsRng;

    let uid = {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes[..]);
        bytes
    };

    let client = {
        let env = libsignal_net::env::PROD.svr3;
        let auth = Auth::from_uid_and_secret(uid, enclave_secret);
        Svr3Client { env, auth }
    };

    let secret = make_secret(&mut rng);
    println!("{}: {}", "Secret to be stored".cyan(), hex::encode(secret));
    let tries = nonzero!(10u32);

    let share_set_bytes = {
        let opaque_share_set = client
            .backup(PASSWORD, secret, tries, &mut rng)
            .await
            .expect("can multi backup");
        opaque_share_set.serialize().expect("can serialize")
    };
    println!("{}: {}", "Share set".cyan(), hex::encode(&share_set_bytes));
    let opaque_share_set =
        OpaqueMaskedShareSet::deserialize(&share_set_bytes).expect("can deserialize");

    {
        println!("{}", "Restoring before rotation...".cyan());
        let restored = client
            .restore(PASSWORD, opaque_share_set.clone(), &mut rng)
            .await
            .expect("can multi restore");
        assert_eq!(secret, restored.value);
        println!(
            "{}: {}",
            "Restored secret".cyan(),
            &hex::encode(restored.value)
        );
        assert_eq!(tries.get() - 1, restored.tries_remaining);
        println!("{}: {}", "Tries remaining".cyan(), restored.tries_remaining);
    }

    {
        println!("{}", "Rotating secret".cyan());
        client
            .rotate(opaque_share_set.clone(), &mut rng)
            .await
            .expect("can rotate");
    };

    println!("{}", "Restoring after rotation...".cyan());
    let restored = {
        client
            .restore(PASSWORD, opaque_share_set.clone(), &mut rng)
            .await
            .expect("can multi restore")
    };
    assert_eq!(secret, restored.value);
    println!(
        "{}: {}",
        "Restored secret".cyan(),
        &hex::encode(restored.value)
    );

    assert_eq!(tries.get() - 2, restored.tries_remaining);
    println!("{}: {}", "Tries remaining".cyan(), restored.tries_remaining);

    println!("{}...", "Querying...".cyan());
    let query_result = client.query().await.expect("can query");
    println!("{}: {}", "Tries remaining".cyan(), query_result);

    println!("{}...", "Removing the secret".cyan());
    client.remove().await.expect("can remove");
    // The next attempt to restore should fail
    {
        let failed_restore_result = client.restore(PASSWORD, opaque_share_set, &mut rng).await;
        assert_matches!(failed_restore_result, Err(Error::DataMissing));
    }
    println!("{}.", "Done".green());
}

fn make_secret(rng: &mut impl CryptoRngCore) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes[..]);
    bytes
}

fn parse_auth_secret(b64: &str) -> [u8; 32] {
    BASE64_STANDARD
        .decode(b64)
        .expect("valid b64")
        .try_into()
        .expect("secret is 32 bytes")
}

fn init_logger() {
    let _ = env_logger::builder().is_test(true).try_init();
}

fn get_enclave_secret() -> Option<[u8; 32]> {
    std::env::var("LIBSIGNAL_TESTING_ENCLAVE_SECRET")
        .map(|b64| parse_auth_secret(&b64))
        .ok()
}
