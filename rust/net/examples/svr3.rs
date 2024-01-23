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
use std::time::Duration;

use base64::prelude::{Engine, BASE64_STANDARD};
use clap::Parser;
use nonzero_ext::nonzero;
use rand_core::{CryptoRngCore, OsRng, RngCore};

use attest::svr2::RaftConfig;
use libsignal_net::enclave::{EndpointConnection, Nitro, Sgx};
use libsignal_net::env::Svr3Env;
use libsignal_net::infra::certs::RootCertificates;
use libsignal_net::infra::TcpSslTransportConnector;
use libsignal_net::svr::{Auth, SvrConnection};
use libsignal_net::svr3::{OpaqueMaskedShareSet, PpssOps};

const NITRO_TEST_RAFT_CONFIG: RaftConfig = RaftConfig {
    group_id: 2058019258222238426,
    min_voting_replicas: 3,
    max_voting_replicas: 5,
    super_majority: 0,
};

#[derive(Parser, Debug)]
struct Args {
    /// base64 encoding of the auth secret for SGX
    #[arg(long)]
    sgx_secret: String,
    #[arg(long)]
    /// base64 encoding of the auth secret for Nitro
    nitro_secret: String,
    /// Password to be used to protect the data
    #[arg(long)]
    password: String,
}
#[tokio::main]
async fn main() {
    init_logger();
    let args = Args::parse();

    let sgx_secret: [u8; 32] = parse_auth_secret(&args.sgx_secret);
    let nitro_secret: [u8; 32] = parse_auth_secret(&args.nitro_secret);

    let mut rng = OsRng;

    let env = libsignal_net::env::STAGING.svr3;

    let uid = {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes[..]);
        hex::encode(bytes)
    };

    let connect = || async {
        let connection_a =
            EndpointConnection::new(env.sgx(), Duration::from_secs(10), TcpSslTransportConnector);
        let sgx_auth = Auth {
            uid: uid.to_string(),
            secret: sgx_secret,
        };
        let a = SvrConnection::<Sgx>::connect(sgx_auth, connection_a)
            .await
            .expect("can attestedly connect to SGX");

        let connection_b = EndpointConnection::with_custom_properties(
            env.nitro(),
            Duration::from_secs(10),
            TcpSslTransportConnector,
            RootCertificates::Signal,
            Some(&NITRO_TEST_RAFT_CONFIG),
        );
        let nitro_auth = Auth {
            uid: uid.to_string(),
            secret: nitro_secret,
        };
        let b = SvrConnection::<Nitro>::connect(nitro_auth, connection_b)
            .await
            .expect("can attestedly connect to Nitro");

        (a, b)
    };

    let secret = make_secret(&mut rng);
    println!("Secret to be stored: {}", hex::encode(secret));

    let share_set_bytes = {
        let opaque_share_set = Svr3Env::backup(
            &mut connect().await,
            &args.password,
            secret,
            nonzero!(10u32),
            &mut rng,
        )
        .await
        .expect("can multi backup");
        opaque_share_set.serialize().expect("can serialize")
    };
    println!("Share set: {}", hex::encode(&share_set_bytes));

    let restored = {
        let opaque_share_set =
            OpaqueMaskedShareSet::deserialize(&share_set_bytes).expect("can deserialize");
        Svr3Env::restore(
            &mut connect().await,
            &args.password,
            opaque_share_set,
            &mut rng,
        )
        .await
        .expect("can mutli restore")
    };
    println!("Restored secret: {}", hex::encode(restored));

    assert_eq!(secret, restored);
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
//
