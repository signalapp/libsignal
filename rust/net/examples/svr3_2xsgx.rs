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

use async_trait::async_trait;
use attest::svr2::RaftConfig;
use base64::prelude::{Engine, BASE64_STANDARD};
use clap::Parser;
use hex_literal::hex;
use http::HeaderName;
use libsignal_net::auth::Auth;
use libsignal_net::connect_state::{ConnectState, SUGGESTED_CONNECT_CONFIG};
use libsignal_net::enclave::{
    self, EnclaveEndpoint, EnclaveEndpointConnection, EndpointParams, MrEnclave, PpssSetup, Sgx,
    Svr3Flavor,
};
use libsignal_net::env::{
    ConnectionConfig, ConnectionProxyConfig, DomainConfig, PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G,
};
use libsignal_net::infra::certs::RootCertificates;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::utils::ObservableEvent;
use libsignal_net::svr::SvrConnection;
use libsignal_net::svr3::traits::*;
use libsignal_net::svr3::OpaqueMaskedShareSet;
use libsignal_net_infra::route::DirectOrProxyProvider;
use libsignal_net_infra::EnableDomainFronting;
use nonzero_ext::nonzero;
use rand_core::{CryptoRngCore, OsRng, RngCore};

const TEST_SERVER_CERT: RootCertificates =
    RootCertificates::FromStaticDers(&[include_bytes!("../res/sgx_test_server_cert.cer")]);
const TEST_SERVER_RAFT_CONFIG: &RaftConfig = &RaftConfig {
    min_voting_replicas: 1,
    max_voting_replicas: 3,
    super_majority: 0,
    group_id: 5873791967879921865,
};
const TEST_SERVER_DOMAIN_CONFIG: DomainConfig = DomainConfig {
    ip_v4: &[],
    ip_v6: &[],
    connect: ConnectionConfig {
        hostname: "backend1.svr3.test.signal.org",
        port: nonzero!(443_u16),
        cert: TEST_SERVER_CERT,
        confirmation_header_name: None,
        proxy: Some(ConnectionProxyConfig {
            path_prefix: "/svr3-test",
            configs: [PROXY_CONFIG_F_STAGING, PROXY_CONFIG_G],
        }),
    },
};
const TEST_SERVER_ENDPOINT_PARAMS: EndpointParams<'static, Sgx> = EndpointParams {
    mr_enclave: MrEnclave::new(&hex!(
        "acb1973aa0bbbd14b3b4e06f145497d948fd4a98efc500fcce363b3b743ec482"
    )),
    raft_config: TEST_SERVER_RAFT_CONFIG,
};

pub struct TwoForTwoEnv<'a, A, B>(EnclaveEndpoint<'a, A>, EnclaveEndpoint<'a, B>)
where
    A: Svr3Flavor,
    B: Svr3Flavor;

impl<A, B> PpssSetup for TwoForTwoEnv<'_, A, B>
where
    A: Svr3Flavor + Send,
    B: Svr3Flavor + Send,
{
    type ConnectionResults = (
        Result<SvrConnection<A>, enclave::Error>,
        Result<SvrConnection<B>, enclave::Error>,
    );
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

struct Client {
    env: TwoForTwoEnv<'static, Sgx, Sgx>,
    auth_a: Auth,
    auth_b: Auth,
}

#[async_trait]
impl Svr3Connect for Client {
    type Env = TwoForTwoEnv<'static, Sgx, Sgx>;

    async fn connect<'s>(&'s self) -> <Self::Env as PpssSetup>::ConnectionResults {
        let connect_state = ConnectState::new(SUGGESTED_CONNECT_CONFIG);
        let network_change_event = ObservableEvent::default();
        let dns_resolver = DnsResolver::new(&network_change_event);

        const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

        let connect_inner = |env: &'s EnclaveEndpoint<'s, Sgx>, ws_config, auth| {
            SvrConnection::connect(
                &connect_state,
                &dns_resolver,
                DirectOrProxyProvider::maybe_proxied(
                    env.route_provider(EnableDomainFronting(false)),
                    None,
                ),
                env.domain_config
                    .connect
                    .confirmation_header_name
                    .map(HeaderName::from_static),
                ws_config,
                &env.params,
                auth,
            )
        };
        let ws_config = |env| {
            EnclaveEndpointConnection::new(env, CONNECT_TIMEOUT, &network_change_event).ws2_config()
        };

        let a = connect_inner(&self.env.0, ws_config(&self.env.0), self.auth_a.clone()).await;

        let b = connect_inner(&self.env.1, ws_config(&self.env.1), self.auth_b.clone()).await;
        (a, b)
    }
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

    let two_sgx_env = {
        let endpoint = EnclaveEndpoint::<Sgx> {
            domain_config: TEST_SERVER_DOMAIN_CONFIG,
            params: TEST_SERVER_ENDPOINT_PARAMS,
        };
        TwoForTwoEnv(endpoint.clone(), endpoint)
    };

    let client = {
        let mut make_uid = || {
            let mut bytes = [0u8; 16];
            rng.fill_bytes(&mut bytes[..]);
            bytes
        };

        let make_auth = |uid: [u8; 16]| Auth::from_uid_and_secret(uid, auth_secret);

        Client {
            env: two_sgx_env,
            auth_a: make_auth(make_uid()),
            auth_b: make_auth(make_uid()),
        }
    };

    let secret = make_secret(&mut rng);
    println!("Secret to be stored: {}", hex::encode(secret));

    let share_set_bytes = {
        let opaque_share_set = client
            .backup(&args.password, secret, nonzero!(10u32), &mut rng)
            .await
            .expect("can multi backup");
        opaque_share_set.serialize().expect("can serialize")
    };
    println!("Share set: {}", hex::encode(&share_set_bytes));

    let restored = {
        let opaque_share_set =
            OpaqueMaskedShareSet::deserialize(&share_set_bytes).expect("can deserialize");
        client
            .restore(&args.password, opaque_share_set, &mut rng)
            .await
            .expect("can multi restore")
    };
    println!("Restored secret: {}", hex::encode(restored.value));

    assert_eq!(secret, restored.value);
}

fn make_secret(rng: &mut impl CryptoRngCore) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes[..]);
    bytes
}
