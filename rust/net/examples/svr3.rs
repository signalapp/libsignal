//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
//! An example program demonstrating the backup and restore capabilities of a built-in Svr3Env.
//!
//! One would need to provide a valid auth secret value used to authenticate to the enclave,
//! as well as the password that will be used to protect the data being stored. Since the
//! actual stored secret data needs to be exactly 32 bytes long, it is generated randomly
//! at each invocation instead of being passed via the command line.

use assert_matches::assert_matches;
use async_trait::async_trait;
use base64::prelude::{Engine, BASE64_STANDARD};
use clap::Parser;
use colored::Colorize as _;
use nonzero_ext::nonzero;
use rand_core::{CryptoRngCore, OsRng, RngCore};

use libsignal_net::auth::Auth;
use libsignal_net::enclave::PpssSetup;
use libsignal_net::env::Svr3Env;
use libsignal_net::infra::tcp_ssl::DirectConnector;
use libsignal_net::infra::TransportConnector;
use libsignal_net::svr3::traits::*;
use libsignal_net::svr3::{Error, OpaqueMaskedShareSet};

#[derive(Parser, Debug)]
struct Args {
    /// base64 encoding of the auth secret for enclaves
    #[arg(long)]
    enclave_secret: Option<String>,
    /// Password to be used to protect the data
    #[arg(long)]
    password: String,
}

struct Svr3Client {
    env: Svr3Env<'static>,
    auth: Auth,
}

type Stream = <DirectConnector as TransportConnector>::Stream;

#[async_trait]
impl Svr3Connect for Svr3Client {
    type Stream = Stream;
    type Env = Svr3Env<'static>;

    async fn connect(&self) -> <Svr3Env as PpssSetup<Stream>>::ConnectionResults {
        self.env.connect_directly(&self.auth).await
    }
}

#[tokio::main]
async fn main() {
    init_logger();
    let args = Args::parse();

    let enclave_secret: [u8; 32] = {
        let b64 = &args
            .enclave_secret
            .or_else(|| std::env::var("LIBSIGNAL_TESTING_ENCLAVE_SECRET").ok())
            .expect("Enclave secret is not set");
        parse_auth_secret(b64)
    };

    let mut rng = OsRng;

    let uid = {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes[..]);
        bytes
    };

    let client = {
        let env = libsignal_net::env::STAGING.svr3;
        let auth = Auth::from_uid_and_secret(uid, enclave_secret);
        Svr3Client { env, auth }
    };

    let secret = make_secret(&mut rng);
    println!("{}: {}", "Secret to be stored".cyan(), hex::encode(secret));
    let tries = nonzero!(10u32);

    let share_set_bytes = {
        let opaque_share_set = client
            .backup(&args.password, secret, tries, &mut rng)
            .await
            .expect("can multi backup");
        opaque_share_set.serialize().expect("can serialize")
    };
    println!("{}: {}", "Share set".cyan(), hex::encode(&share_set_bytes));

    let restored = {
        let opaque_share_set =
            OpaqueMaskedShareSet::deserialize(&share_set_bytes).expect("can deserialize");
        client
            .restore(&args.password, opaque_share_set, &mut rng)
            .await
            .expect("can mutli restore")
    };
    assert_eq!(secret, restored.value);
    println!(
        "{}: {}",
        "Restored secret".cyan(),
        &hex::encode(restored.value)
    );

    assert_eq!(tries.get() - 1, restored.tries_remaining);
    println!("{}: {}", "Tries remaining".cyan(), restored.tries_remaining);

    println!("{}...", "Querying...".cyan());
    let query_result = client.query().await.expect("can query");
    println!("{}: {}", "Tries remaining".cyan(), query_result);

    println!("{}...", "Removing the secret".cyan());
    client.remove().await.expect("can remove");
    // The next attempt to restore should fail
    {
        let opaque_share_set =
            OpaqueMaskedShareSet::deserialize(&share_set_bytes).expect("can deserialize");
        let failed_restore_result = client
            .restore(&args.password, opaque_share_set, &mut rng)
            .await;
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
