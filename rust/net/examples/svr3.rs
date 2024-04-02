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
use libsignal_net::infra::dns::DnsResolver;
use nonzero_ext::nonzero;
use rand_core::{CryptoRngCore, OsRng, RngCore};

use libsignal_net::auth::Auth;
use libsignal_net::enclave::{EnclaveEndpointConnection, Nitro, Sgx, Tpm2Snp};
use libsignal_net::env::Svr3Env;
use libsignal_net::infra::tcp_ssl::DirectConnector as TcpSslTransportConnector;
use libsignal_net::svr::SvrConnection;
use libsignal_net::svr3::{OpaqueMaskedShareSet, PpssOps};

#[derive(Parser, Debug)]
struct Args {
    /// base64 encoding of the auth secret for enclaves
    #[arg(long)]
    enclave_secret: Option<String>,
    /// Password to be used to protect the data
    #[arg(long)]
    password: String,
}
#[tokio::main]
async fn main() {
    init_logger();
    let args = Args::parse();

    let enclave_secret: [u8; 32] = {
        let b64 = &args
            .enclave_secret
            .or_else(|| std::env::var("ENCLAVE_SECRET").ok())
            .expect("Enclave secret is not set");
        parse_auth_secret(b64)
    };

    let mut rng = OsRng;

    let env = libsignal_net::env::STAGING.svr3;

    let uid = {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes[..]);
        bytes
    };
    let auth = Auth::from_uid_and_secret(uid, enclave_secret);

    let connect = || async {
        let connector = TcpSslTransportConnector::new(DnsResolver::default());
        let connection_a = EnclaveEndpointConnection::new(env.sgx(), Duration::from_secs(10));
        let a = SvrConnection::<Sgx, _>::connect(auth.clone(), &connection_a, connector.clone())
            .await
            .expect("can attestedly connect to SGX");

        let connection_b = EnclaveEndpointConnection::new(env.nitro(), Duration::from_secs(10));
        let b = SvrConnection::<Nitro, _>::connect(auth.clone(), &connection_b, connector.clone())
            .await
            .expect("can attestedly connect to Nitro");

        let connection_c = EnclaveEndpointConnection::new(env.tpm2snp(), Duration::from_secs(10));
        let c = SvrConnection::<Tpm2Snp, _>::connect(auth.clone(), &connection_c, connector)
            .await
            .expect("can attestedly connect to Tpm2Snp");
        (a, b, c)
    };

    let secret = make_secret(&mut rng);
    println!("Secret to be stored: {}", hex::encode(secret));

    let share_set_bytes = {
        let opaque_share_set = Svr3Env::backup(
            connect().await,
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
        Svr3Env::restore(connect().await, &args.password, opaque_share_set, &mut rng)
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
