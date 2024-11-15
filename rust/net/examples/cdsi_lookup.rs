//! Example binary that makes CDSI requests.
//!
//! Reads the environment variables `USERNAME` and `PASSWORD` for
//! authentication, then reads phone numbers from stdin until the end of the
//! file.

use std::ops::ControlFlow;
use std::time::Duration;

use clap::Parser;
use http::HeaderName;
use libsignal_net::auth::Auth;
use libsignal_net::cdsi::{CdsiConnection, LookupError, LookupRequest, LookupResponse};
use libsignal_net::enclave::EnclaveEndpointConnection;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::utils::ObservableEvent;
use libsignal_net::infra::AsHttpHeader as _;
use libsignal_net::ws::WebSocketServiceConnectError;
use libsignal_net_infra::connection_manager::{ErrorClass, ErrorClassifier};
use libsignal_net_infra::route::testutils::NoDelay;
use libsignal_net_infra::route::{ComposedConnector, RouteProviderExt, RouteResolver};
use libsignal_net_infra::tcp_ssl::DirectConnector;
use libsignal_net_infra::ws::WebSocketConnectError;
use tokio::io::AsyncBufReadExt as _;
use tokio::time::Instant;

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

type StatelessTlsConnector = libsignal_net::infra::tcp_ssl::StatelessDirect;
type StatelessTcpConnector = libsignal_net::infra::tcp_ssl::StatelessDirect;
type StatelessConnector = ComposedConnector<
    libsignal_net::infra::ws::Stateless,
    ComposedConnector<StatelessTlsConnector, StatelessTcpConnector, WebSocketConnectError>,
    WebSocketConnectError,
>;

#[derive(clap::Parser)]
struct CliArgs {
    #[arg(long, default_value_t = false)]
    use_routes: bool,
    #[arg(long, default_value_t = std::env::var("USERNAME").unwrap())]
    username: String,
    #[arg(long, default_value_t = std::env::var("PASSWORD").unwrap())]
    password: String,
}

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
        return_acis_without_uaks: true,
        ..Default::default()
    };

    let cdsi_env = libsignal_net::env::PROD.cdsi;
    let network_change_event = ObservableEvent::default();
    let resolver = DnsResolver::new(&network_change_event);

    let connected = if use_routes {
        let provider = cdsi_env.route_provider().map_routes(|mut route| {
            route.fragment.headers.extend([auth.as_header()]);
            route
        });
        let delay_policy = NoDelay;
        let confirmation_header_name = cdsi_env
            .domain_config
            .connect
            .confirmation_header_name
            .map(HeaderName::from_static);

        // No need to keep the outcomes updates since we're not reusing the
        // connector.
        let (result, _updates) = libsignal_net::infra::route::connect(
            &RouteResolver::default(),
            &delay_policy,
            &provider,
            &resolver,
            StatelessConnector::default(),
            |error| {
                let service_error = WebSocketServiceConnectError::from_websocket_error(
                    error,
                    confirmation_header_name.as_ref(),
                    Instant::now(),
                );

                match service_error.classify() {
                    ErrorClass::Intermittent => ControlFlow::Continue(()),
                    ErrorClass::RetryAt(instant) => ControlFlow::Break(format!(
                        "retry in {}s",
                        instant.saturating_duration_since(Instant::now()).as_secs()
                    )),
                    ErrorClass::Fatal => ControlFlow::Break(service_error.to_string()),
                }
            },
        )
        .await;

        CdsiConnection::connect_over(
            result.unwrap(),
            &cdsi_env.params,
            libsignal_net_infra::ws2::Config {
                local_idle_timeout: Duration::from_secs(10),
                remote_idle_ping_timeout: Duration::from_secs(10),
                remote_idle_disconnect_timeout: Duration::from_secs(30),
            },
        )
        .await
    } else {
        let endpoint_connection = EnclaveEndpointConnection::new(
            &cdsi_env,
            Duration::from_secs(10),
            &network_change_event,
        );
        let transport_connection = DirectConnector::new(DnsResolver::new(&network_change_event));
        CdsiConnection::connect(&endpoint_connection, transport_connection, auth).await
    }
    .unwrap();

    let cdsi_response = cdsi_lookup(connected, request, Duration::from_secs(10))
        .await
        .unwrap();

    println!("{:?}", cdsi_response);
}
