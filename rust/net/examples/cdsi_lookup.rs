//! Example binary that makes CDSI requests.
//!
//! Reads the environment variables `USERNAME` and `PASSWORD` for
//! authentication, then reads phone numbers from stdin until the end of the
//! file.

use std::time::Duration;

use libsignal_net::auth::Auth;
use libsignal_net::cdsi::{CdsiConnection, LookupError, LookupRequest, LookupResponse};
use libsignal_net::enclave::{Cdsi, EnclaveEndpointConnection};
use libsignal_net::infra::connection_manager::ConnectionManager;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::tcp_ssl::DirectConnector as TcpSslTransportConnector;
use libsignal_net::infra::utils::ObservableEvent;
use libsignal_net::infra::TransportConnector;
use tokio::io::AsyncBufReadExt as _;

async fn cdsi_lookup(
    auth: Auth,
    endpoint: &EnclaveEndpointConnection<Cdsi, impl ConnectionManager>,
    transport_connector: impl TransportConnector,
    request: LookupRequest,
    timeout: Duration,
) -> Result<LookupResponse, LookupError> {
    let connected = CdsiConnection::connect(endpoint, transport_connector, auth).await?;
    let (_token, remaining_response) = libsignal_net::infra::utils::timeout(
        timeout,
        LookupError::ConnectionTimedOut,
        connected.send_request(request),
    )
    .await?;

    remaining_response.collect().await
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let username = std::env::var("USERNAME").unwrap();
    let password = std::env::var("PASSWORD").unwrap();
    let mut new_e164s = vec![];
    let mut lines = tokio::io::BufReader::new(tokio::io::stdin()).lines();

    while let Some(line) = lines.next_line().await.unwrap() {
        new_e164s.push(line.parse().unwrap());
    }

    let request = LookupRequest {
        new_e164s,
        acis_and_access_keys: vec![],
        return_acis_without_uaks: true,
        ..Default::default()
    };
    let env = libsignal_net::env::PROD;
    let network_change_event = ObservableEvent::default();
    let endpoint_connection =
        EnclaveEndpointConnection::new(&env.cdsi, Duration::from_secs(10), &network_change_event);
    let transport_connection =
        TcpSslTransportConnector::new(DnsResolver::new(&network_change_event));
    let cdsi_response = cdsi_lookup(
        Auth { username, password },
        &endpoint_connection,
        transport_connection,
        request,
        Duration::from_secs(10),
    )
    .await
    .unwrap();

    println!("{:?}", cdsi_response);
}
