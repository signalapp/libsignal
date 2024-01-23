//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
//! An example program that demonstrates how to implement 2-out-of-2 PPSS setup
//! using just a single enclave type (SGX in this case).
//!
//! One would need to provide a valid auth secret value used to authenticate to the enclave,
//! as well as the password that will be used to protect the data being stored. Since the
//! actual stored secret data needs to be exactly 32 bytes long, it is generated randomly
//! at each invocation instead of being passed via the command line.
use std::time::Duration;

use base64::prelude::{Engine, BASE64_STANDARD};
use clap::Parser;
use hex_literal::hex;
use nonzero_ext::nonzero;
use rand_core::{CryptoRngCore, OsRng, RngCore};

use attest::svr2::RaftConfig;
use libsignal_net::enclave::{
    EnclaveEndpoint, EndpointConnection, MrEnclave, PpssSetup, Sgx, Svr3Flavor,
};
use libsignal_net::infra::certs::RootCertificates;
use libsignal_net::infra::TcpSslTransportConnector;
use libsignal_net::svr::{Auth, SvrConnection};
use libsignal_net::svr3::{OpaqueMaskedShareSet, PpssOps};

const TEST_SERVER_CERT_DER: &[u8] = include_bytes!("../res/sgx_test_server_cert.cer");
const TEST_SERVER_RAFT_CONFIG: RaftConfig = RaftConfig {
    min_voting_replicas: 1,
    max_voting_replicas: 3,
    super_majority: 0,
    group_id: 5873791967879921865,
};

pub struct TwoForTwoEnv<'a, A, B>(EnclaveEndpoint<'a, A>, EnclaveEndpoint<'a, B>)
where
    A: Svr3Flavor,
    B: Svr3Flavor;

impl<'a, A, B> PpssSetup for TwoForTwoEnv<'a, A, B>
where
    A: Svr3Flavor,
    B: Svr3Flavor,
{
    type Connections = (SvrConnection<A>, SvrConnection<B>);
    type ServerIds = [u64; 2];

    fn server_ids() -> Self::ServerIds {
        [0, 1]
    }
}

#[derive(Parser, Debug)]
struct Args {
    /// base64 encoding of the auth secret
    #[arg(long)]
    auth_secret: String,
    /// Password to be used to protect the data
    #[arg(long)]
    password: String,
}
#[tokio::main]
async fn main() {
    let args = Args::parse();

    let auth_secret: [u8; 32] = {
        BASE64_STANDARD
            .decode(&args.auth_secret)
            .expect("valid b64")
            .try_into()
            .expect("secret is 32 bytes")
    };

    let mut rng = OsRng;

    let mut make_uid = || {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes[..]);
        hex::encode(bytes)
    };

    let make_auth = |uid: &str| Auth {
        uid: uid.to_string(),
        secret: auth_secret,
    };

    let two_sgx_env = {
        let endpoint = EnclaveEndpoint::<Sgx> {
            host: "backend1.svr3.test.signal.org",
            mr_enclave: MrEnclave::new(&hex!(
                "acb1973aa0bbbd14b3b4e06f145497d948fd4a98efc500fcce363b3b743ec482"
            )),
        };
        TwoForTwoEnv(endpoint, endpoint)
    };

    let (uid_a, uid_b) = (make_uid(), make_uid());

    let connect = || async {
        let connection_a = EndpointConnection::with_custom_properties(
            two_sgx_env.0,
            Duration::from_secs(10),
            TcpSslTransportConnector,
            RootCertificates::FromDer(TEST_SERVER_CERT_DER.to_vec()),
            Some(&TEST_SERVER_RAFT_CONFIG),
        );

        let a = SvrConnection::connect(make_auth(&uid_a), connection_a)
            .await
            .expect("can attestedly connect");

        let connection_b = EndpointConnection::with_custom_properties(
            two_sgx_env.1,
            Duration::from_secs(10),
            TcpSslTransportConnector,
            RootCertificates::FromDer(TEST_SERVER_CERT_DER.to_vec()),
            Some(&TEST_SERVER_RAFT_CONFIG),
        );

        let b = SvrConnection::connect(make_auth(&uid_b), connection_b)
            .await
            .expect("can attestedly connect");
        (a, b)
    };

    let secret = make_secret(&mut rng);
    println!("Secret to be stored: {}", hex::encode(secret));

    let share_set_bytes = {
        let opaque_share_set = TwoForTwoEnv::backup(
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
        TwoForTwoEnv::restore(
            &mut connect().await,
            &args.password,
            opaque_share_set,
            &mut rng,
        )
        .await
        .expect("can multi restore")
    };
    println!("Restored secret: {}", hex::encode(restored));

    assert_eq!(secret, restored);
}

fn make_secret(rng: &mut impl CryptoRngCore) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes[..]);
    bytes
}
