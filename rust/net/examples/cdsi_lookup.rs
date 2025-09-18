//! Example binary that makes CDSI requests.
//!
//! Reads the environment variables `USERNAME` and `PASSWORD` for
//! authentication, then reads phone numbers from stdin until the end of the
//! file.

use std::time::Duration;

use clap::Parser;
use http::HeaderName;
use libsignal_net::auth::Auth;
use libsignal_net::cdsi::{CdsiConnection, LookupError, LookupRequest, LookupResponse};
use libsignal_net::connect_state::{ConnectState, ConnectionResources, SUGGESTED_CONNECT_CONFIG};
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net_infra::EnableDomainFronting;
use libsignal_net_infra::route::DirectOrProxyProvider;
use libsignal_net_infra::utils::no_network_change_events;
use tokio::io::AsyncBufReadExt as _;

async fn cdsi_lookup(
    cdsi: CdsiConnection,
    request: LookupRequest,
    timeout: Duration,
) -> Result<LookupResponse, LookupError> {
    let (_token, remaining_response) = libsignal_net::infra::utils::timeout(
        timeout,
        LookupError::AllConnectionAttemptsFailed,
        cdsi.send_request(request),
    )
    .await?;

    remaining_response.collect().await
}

#[derive(Copy, Clone, Debug, strum::EnumString, strum::Display)]
#[strum(serialize_all = "lowercase")]
enum Environment {
    Staging,
    Prod,
}

#[derive(clap::Parser)]
struct CliArgs {
    #[arg(long, env = "USERNAME")]
    username: String,
    #[arg(long, env = "PASSWORD")]
    password: String,
    #[arg(long, default_value_t = Environment::Prod)]
    environment: Environment,
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let CliArgs {
        username,
        password,
        environment,
    } = CliArgs::parse();

    let auth = Auth { username, password };

    let mut new_e164s = vec![];
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    while let Some(line) = lines.next_line().await.unwrap() {
        new_e164s.push(line.parse().unwrap());
    }

    let request = LookupRequest {
        new_e164s,
        acis_and_access_keys: vec![],
        ..Default::default()
    };

    let cdsi_env = match environment {
        Environment::Prod => libsignal_net::env::PROD.cdsi,
        Environment::Staging => libsignal_net::env::STAGING.cdsi,
    };
    let resolver = DnsResolver::new(&no_network_change_events());

    let connected = {
        let confirmation_header_name = cdsi_env
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
    }
    .unwrap();

    let cdsi_response = cdsi_lookup(connected, request, Duration::from_secs(10))
        .await
        .unwrap();

    println!("{cdsi_response:?}");
}
