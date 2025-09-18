//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;
use std::future::Future;
use std::io::Error as IoError;
use std::num::NonZeroU16;
use std::pin::Pin;
use std::sync::Arc;

use clap::Parser;
use futures_util::FutureExt;
use http::HeaderMap;
use http::uri::{Authority, PathAndQuery, Scheme};
use libsignal_cli_utils::args::{parse_base64_bytes, parse_protocol_address};
use libsignal_core::{Aci, DeviceId};
use libsignal_net::certs::SIGNAL_ROOT_CERTIFICATES;
use libsignal_net::chat::noise::{Authorization, ChatNoiseConnector, ChatNoiseRoute, ConnectMeta};
use libsignal_net::connect_state::{ConnectState, ConnectionResources, SUGGESTED_CONNECT_CONFIG};
use libsignal_net::infra::AsyncDuplexStream;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::host::Host;
use libsignal_net::infra::noise::{NoiseConnector, NoiseDirectConnector};
use libsignal_net::infra::route::provider::EmptyProvider;
use libsignal_net::infra::route::{
    ComposedConnector, ConnectError, Connector as _, DirectOrProxyProvider, DirectTcpRouteProvider,
    HttpVersion, HttpsProvider, NoDelay, RouteResolver, TcpRoute, TlsRouteProvider, UnresolvedHost,
    WebSocketProvider, WebSocketRouteFragment,
};
use libsignal_net::infra::utils::no_network_change_events;
use libsignal_net::infra::ws::{StreamWithResponseHeaders, WebSocketTransport};
use libsignal_net_grpc::proto::chat::account::accounts_anonymous_client::AccountsAnonymousClient;
use libsignal_net_grpc::proto::chat::account::accounts_client::AccountsClient;
use libsignal_net_grpc::proto::chat::account::{
    GetAccountIdentityRequest, LookupUsernameHashRequest, LookupUsernameHashResponse,
};
use static_assertions::assert_impl_all;
use usernames::Username;

#[derive(Parser)]
struct CliArgs {
    /// the host:port pair to connect to
    host_port: String,

    /// if set, connects via Noise Direct; otherwise connects via noise-over-websocket
    #[arg(long, conflicts_with = "sni")]
    direct: bool,

    /// optional SNI override; if not set, the host name will be used
    #[arg(long)]
    sni: Option<String>,

    /// base64-encoded static public key for the server
    #[arg(long, value_parser=parse_base64_bytes::<32>)]
    server_public_key: [u8; 32],

    /// client address to authenticate as; if not set, the connection will be unauthenticated
    #[arg(long, requires = "client_private_key", value_parser=parse_protocol_address::<Aci>)]
    authenticated: Option<(Aci, DeviceId)>,

    /// corresponding base64-encoded private key for the authenticated address
    #[arg(long, requires = "authenticated", value_parser=parse_base64_bytes::<32>)]
    client_private_key: Option<[u8; 32]>,

    /// for an unauthenticated connection, the username to look up
    #[arg(long, value_parser=parse_username, conflicts_with = "authenticated")]
    username: Option<Arc<Username>>,
}

fn parse_username(input: &str) -> Result<Arc<Username>, usernames::UsernameError> {
    Username::new(input).map(Arc::new)
}

/// Simple [`tonic::client::GrpcService`] implementation over a [hyper] H2 client.
struct GrpcConnection {
    /// The `authority` for each request.
    authority: Authority,
    /// A request sender for the HTTP2 connection.
    send_request: hyper::client::conn::http2::SendRequest<tonic::body::Body>,
}

impl tower::Service<http::Request<tonic::body::Body>> for GrpcConnection {
    type Response = http::Response<hyper::body::Incoming>;

    type Error = hyper::Error;

    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.send_request.poll_ready(cx)
    }

    fn call(&mut self, mut req: http::Request<tonic::body::Body>) -> Self::Future {
        let mut parts = req.uri().clone().into_parts();
        parts.authority = Some(self.authority.clone());
        parts.scheme = Some(Scheme::HTTP);

        *req.uri_mut() = http::Uri::from_parts(parts).unwrap();
        self.send_request.clone().send_request(req).boxed()
    }
}

assert_impl_all!(GrpcConnection: tonic::client::GrpcService<tonic::body::Body>);

trait WsPath {
    fn ws_path(&self) -> &'static str;
}

impl WsPath for Authorization {
    fn ws_path(&self) -> &'static str {
        match self {
            Authorization::Authenticated { .. } => "/authenticated",
            Authorization::Anonymous { .. } => "/anonymous",
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let CliArgs {
        authenticated,
        username,
        client_private_key,
        server_public_key,
        direct,
        host_port,
        sni,
    } = CliArgs::parse();
    let (host, port) = host_port
        .split_once(':')
        .map(|(host, port)| (host, port.parse().expect("invalid port")))
        .unwrap_or((
            &host_port,
            if direct { 443 } else { 444 }.try_into().unwrap(),
        ));

    let auth = match (authenticated, client_private_key) {
        (None, None) => Authorization::Anonymous { server_public_key },
        (Some((aci, device_id)), Some(client_private_key)) => Authorization::Authenticated {
            aci,
            device_id,
            server_public_key,
            client_private_key,
        },
        _ => unreachable!("disallowed by argument parsing"),
    };

    let connect_state = Arc::new(ConnectState::new(SUGGESTED_CONNECT_CONFIG));
    let resolver = DnsResolver::new(&no_network_change_events());

    let authenticated_request = match &auth {
        Authorization::Anonymous { .. } => false,
        Authorization::Authenticated { .. } => true,
    };

    let host = Arc::<str>::from(host);
    let authority = host_port.parse().unwrap();

    let stream = if direct {
        log::info!("connecting via NoiseDirect");
        connect_noise_direct(connect_state, auth, &resolver, host, port).await
    } else {
        log::info!("connecting via websocket");
        let sni = sni.map(Arc::<str>::from).unwrap_or_else(|| host.clone());
        let path = auth.ws_path();
        connect_over_websocket(connect_state, auth, &resolver, host, sni, path, port).await
    }
    .expect("can connect");

    let service = {
        let (send_request, connection) = hyper::client::conn::http2::handshake(
            hyper_util::rt::TokioExecutor::new(),
            hyper_util::rt::TokioIo::new(stream),
        )
        .await
        .expect("can connect HTTP2");
        tokio::spawn(connection);
        GrpcConnection {
            authority,
            send_request,
        }
    };

    if authenticated_request {
        let mut account_service = AccountsClient::new(service);
        // Sample request
        let request = GetAccountIdentityRequest {};
        println!("sending request: {request:?}");
        let response = account_service.get_account_identity(request).await.unwrap();
        println!("got response {response:?}")
    } else {
        let username = username.expect("--username is required for unauthenticated request");

        let mut account_service = AccountsAnonymousClient::new(service);
        // Sample request
        let request = LookupUsernameHashRequest {
            username_hash: username.hash().into(),
        };
        println!("sending request: {request:?}");
        match account_service.lookup_username_hash(request).await {
            Ok(response) => {
                let LookupUsernameHashResponse { service_identifier } = response.into_inner();
                println!(
                    "{username}: {}",
                    service_identifier
                        .unwrap()
                        .try_into_service_id()
                        .unwrap()
                        .service_id_string()
                )
            }
            Err(status) if status.code() == tonic::Code::NotFound => println!("not found"),
            Err(status) => println!("unexpected failure: {status}"),
        }
    }
}

async fn connect_over_websocket(
    connect_state: Arc<std::sync::Mutex<ConnectState>>,
    auth: Authorization,
    resolver: &DnsResolver,
    host: Arc<str>,
    sni: Arc<str>,
    path: &'static str,
    port: NonZeroU16,
) -> Result<Box<dyn AsyncDuplexStream>, IoError> {
    let sni = Host::Domain(sni);
    let (
        StreamWithResponseHeaders {
            stream,
            response_headers: _,
        },
        _route_info,
    ) = ConnectionResources {
        connect_state: &connect_state,
        dns_resolver: resolver,
        network_change_event: &no_network_change_events(),
        confirmation_header_name: None,
    }
    .connect_ws(
        WebSocketProvider::new(
            WebSocketRouteFragment {
                endpoint: PathAndQuery::from_static(path),
                ws_config: Default::default(),
                headers: HeaderMap::default(),
            },
            HttpsProvider::new(
                host.clone(),
                HttpVersion::Http1_1,
                EmptyProvider::default(),
                TlsRouteProvider::new(
                    SIGNAL_ROOT_CERTIFICATES,
                    None,
                    sni.clone(),
                    DirectOrProxyProvider::direct(DirectTcpRouteProvider::new(host, port)),
                ),
            ),
        ),
        libsignal_net::infra::ws::Stateless,
        "noise",
    )
    .await
    .unwrap();
    log::info!("websocket connected, trying Noise");
    let stream = ChatNoiseConnector(NoiseConnector)
        .connect_over(
            WebSocketTransport(stream),
            (
                auth,
                ConnectMeta {
                    user_agent: "libsignal example".to_owned(),
                    ..Default::default()
                },
            ),
            "noise",
        )
        .await
        .map_err(IoError::other)?;

    Ok(Box::new(stream))
}

async fn connect_noise_direct(
    connect_state: Arc<std::sync::Mutex<ConnectState>>,
    auth: Authorization,
    resolver: &DnsResolver,
    host: Arc<str>,
    port: NonZeroU16,
) -> Result<Box<dyn AsyncDuplexStream>, IoError> {
    // TODO use connect state instead of connecting directly.
    drop(connect_state);
    let (result, _updates) = libsignal_net::infra::route::connect(
        &RouteResolver { allow_ipv6: true },
        NoDelay,
        std::iter::once(ChatNoiseRoute {
            fragment: (
                auth,
                ConnectMeta {
                    user_agent: "libsignal example".to_owned(),
                    ..Default::default()
                },
            ),
            inner: TcpRoute {
                address: UnresolvedHost(host),
                port,
            },
        }),
        resolver,
        ComposedConnector::new(
            ChatNoiseConnector(NoiseConnector),
            NoiseDirectConnector(libsignal_net::infra::tcp_ssl::StatelessTcp),
        ),
        (),
        "noise",
        |_: libsignal_net::chat::noise::ConnectError| {
            std::ops::ControlFlow::<Infallible>::Continue(())
        },
    )
    .await;

    let stream = result.map_err(|e| {
        IoError::other(match e {
            ConnectError::NoResolvedRoutes => "no resolved routes",
            ConnectError::AllAttemptsFailed => "all attempts failed",
        })
    })?;

    Ok(Box::new(stream))
}
