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
use libsignal_net::connect_state::{ConnectState, SUGGESTED_CONNECT_CONFIG};
use libsignal_net::enclave::EnclaveEndpointConnection;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::utils::ObservableEvent;
use libsignal_net_infra::route::DirectOrProxyProvider;
use libsignal_net_infra::tcp_ssl::DirectConnector;
use libsignal_net_infra::EnableDomainFronting;
use tokio::io::AsyncBufReadExt as _;

async fn cdsi_lookup(
    cdsi: CdsiConnection,
    request: LookupRequest,
    timeout: Duration,
) -> Result<LookupResponse, LookupError> {
    let (_token, remaining_response) = libsignal_net::infra::utils::timeout(
        timeout,
        LookupError::ConnectionTimedOut,
        cdsi.send_request(request),
    )
    .await?;

    remaining_response.collect().await
}

#[derive(clap::Parser)]
struct CliArgs {
    #[arg(long, default_value_t = false)]
    use_routes: bool,
    #[arg(long, default_value_t = std::env::var("USERNAME").unwrap())]
    username: String,
    #[arg(long, default_value_t = std::env::var("PASSWORD").unwrap())]
    password: String,
}

const WS2_CONFIG: libsignal_net_infra::ws2::Config = libsignal_net_infra::ws2::Config {
    local_idle_timeout: Duration::from_secs(10),
    remote_idle_ping_timeout: Duration::from_secs(10),
    remote_idle_disconnect_timeout: Duration::from_secs(30),
};

#[tokio::main]
async fn main() {
    env_logger::init();

    let CliArgs {
        use_routes,
        username,
        password,
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

    let cdsi_env = libsignal_net::env::PROD.cdsi;
    let network_change_event = ObservableEvent::default();
    let resolver = DnsResolver::new(&network_change_event);

    let connected = if use_routes {
        let confirmation_header = cdsi_env
            .domain_config
            .connect
            .confirmation_header_name
            .map(HeaderName::from_static);
        let connect_state = ConnectState::new(SUGGESTED_CONNECT_CONFIG);

        CdsiConnection::connect_with(
            &connect_state,
            &resolver,
            DirectOrProxyProvider::maybe_proxied(
                cdsi_env.route_provider(EnableDomainFronting(false)),
                None,
            ),
            confirmation_header,
            WS2_CONFIG,
            &cdsi_env.params,
            auth,
        )
        .await
    } else {
        let endpoint_connection = EnclaveEndpointConnection::new(
            &cdsi_env,
            Duration::from_secs(10),
            &network_change_event,
        );
        let transport_connection = DirectConnector::new(resolver);
        CdsiConnection::connect(&endpoint_connection, transport_connection, auth).await
    }
    .unwrap();

    let cdsi_response = cdsi_lookup(connected, request, Duration::from_secs(10))
        .await
        .unwrap();

    println!("{:?}", cdsi_response);
}
