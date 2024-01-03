//! Example binary that makes CDSI requests.
//!
//! Reads the environment variables `USERNAME` and `PASSWORD` for
//! authentication, then reads phone numbers from stdin until the end of the
//! file.

use std::time::Duration;

use tokio::io::AsyncBufReadExt as _;

use libsignal_net::cdsi::{
    Auth, CdsiConnection, CdsiConnectionParams, Error, LookupRequest, LookupResponse,
};
use libsignal_net::enclave::EndpointConnection;
use libsignal_net::infra::errors::NetError;
use libsignal_net::infra::TcpSslTransportConnector;

async fn cdsi_lookup(
    auth: Auth,
    cdsi: &impl CdsiConnectionParams,
    request: LookupRequest,
    timeout: Duration,
) -> Result<LookupResponse, Error> {
    let connected = CdsiConnection::connect(cdsi, auth).await?;
    let (_token, remaining_response) = libsignal_net::utils::timeout(
        timeout,
        Error::Net(NetError::Timeout),
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
    let env = &libsignal_net::env::PROD;
    let cdsi_response = cdsi_lookup(
        Auth { username, password },
        &EndpointConnection::new(env.cdsi, Duration::from_secs(10), TcpSslTransportConnector),
        request,
        Duration::from_secs(10),
    )
    .await
    .unwrap();

    println!("{:?}", cdsi_response);
}
