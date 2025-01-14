//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;
use std::future::Future;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::TryFutureExt as _;
use http::uri::Authority;
use http::Uri;
use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use pin_project::pin_project;
use static_assertions::assert_impl_all;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::either::Either;

use crate::errors::{LogSafeDisplay, TransportConnectError};
use crate::host::Host;
use crate::route::{
    ComposedConnector, Connector, ConnectorExt as _, HttpProxyAuth, HttpProxyRouteFragment,
    HttpsProxyRoute, ProxyTarget,
};
use crate::ws::error::HttpFormatError;
use crate::{AsHttpHeader, AsyncDuplexStream, Connection, TransportInfo};

/// An [`AsyncDuplexStream`] created by an HTTP [`CONNECT`] request.
///
/// [`CONNECT`]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/CONNECT
#[derive(Debug)]
#[pin_project]
pub struct HttpProxyStream {
    #[pin]
    inner: TokioIo<hyper::upgrade::Upgraded>,
    info: TransportInfo,
}

assert_impl_all!(HttpProxyStream: AsyncDuplexStream);

type StatelessTcpConnector = super::super::StatelessDirect;
type StatelessTlsConnector = ComposedConnector<
    super::super::StatelessDirect,
    super::super::StatelessDirect,
    TransportConnectError,
>;

impl Connector<HttpsProxyRoute<IpAddr>, ()> for super::StatelessProxied {
    type Connection = HttpProxyStream;

    type Error = TransportConnectError;

    fn connect_over(
        &self,
        (): (),
        route: HttpsProxyRoute<IpAddr>,
        log_tag: Arc<str>,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let HttpsProxyRoute { fragment, inner } = route;
        async move {
            let tls_connector = StatelessTlsConnector::default();
            let tcp_connector = StatelessTcpConnector::default();
            let inner = inner
                .map_either(
                    |tls| {
                        tls_connector
                            .connect(tls, log_tag.clone())
                            .map_ok(Either::Left)
                    },
                    |tcp| {
                        tcp_connector
                            .connect(tcp, log_tag.clone())
                            .map_ok(Either::Right)
                    },
                )
                .await?;
            let info = inner.transport_info();

            let HttpProxyRouteFragment {
                target_host,
                target_port,
                authorization,
            } = fragment;

            let target_host = match target_host {
                ProxyTarget::ResolvedLocally(addr) => Host::Ip(addr),
                ProxyTarget::ResolvedRemotely { name } => Host::Domain(name),
            };

            match connect_https11_proxy(
                inner,
                (target_host.as_deref(), target_port),
                authorization.as_ref(),
            )
            .await
            {
                Ok(connection) => Ok(HttpProxyStream {
                    inner: TokioIo::new(connection),
                    info,
                }),
                Err(e) => {
                    log::info!("[{log_tag}] failed to connect via HTTP proxy: {e}");
                    Err(TransportConnectError::ProxyProtocol)
                }
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
enum ConnectError {
    Transport(#[from] Box<TransportConnectError>),
    HttpConnectionFailed(hyper::Error),
    HttpUpgradeFailed(hyper::Error),
    HttpRequestRejected(http::StatusCode),
    HttpRequestFailed(hyper::Error),
    InvalidRequest(http::Error),
    InvalidUri(http::uri::InvalidUri),
}

impl Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Transport(transport_connect_error) => {
                write!(f, "transport: {}", transport_connect_error)
            }
            ConnectError::HttpConnectionFailed(err) => {
                write!(f, "HTTP connection failed: {}", LogSafeHyperError(err))
            }
            ConnectError::HttpUpgradeFailed(error) => {
                write!(f, "HTTP upgrade failed: {}", LogSafeHyperError(error))
            }
            ConnectError::HttpRequestRejected(status_code) => {
                write!(f, "HTTP upgrade rejected: {status_code}")
            }
            ConnectError::HttpRequestFailed(error) => {
                write!(f, "HTTP request send failed: {}", LogSafeHyperError(error))
            }
            ConnectError::InvalidRequest(error) => {
                write!(
                    f,
                    "HTTP request was invalid: {}",
                    HttpFormatError::from(error)
                )
            }
            ConnectError::InvalidUri(error) => {
                write!(f, "URI was invalid: {}", error)
            }
        }
    }
}

async fn connect_https11_proxy(
    tls_to_proxy: impl AsyncDuplexStream + 'static,
    host_port: (Host<&str>, NonZeroU16),
    authorization: Option<&HttpProxyAuth>,
) -> Result<hyper::upgrade::Upgraded, ConnectError> {
    let http_request = make_connect_request(host_port, authorization)?;

    let (mut send_request, connection) = hyper::client::conn::http1::Builder::new()
        .handshake(TokioIo::new(tls_to_proxy))
        .await
        .map_err(ConnectError::HttpConnectionFailed)?;

    // Run the HTTP processing future on a task. This will end on its own when
    // there aren't any more request senders.
    tokio::task::spawn(connection.with_upgrades());

    let response = send_request
        .send_request(http_request)
        .await
        .map_err(ConnectError::HttpRequestFailed)?;

    let status = response.status();
    if !status.is_success() {
        return Err(ConnectError::HttpRequestRejected(status));
    }

    hyper::upgrade::on(response)
        .await
        .map_err(ConnectError::HttpUpgradeFailed)
}

struct LogSafeHyperError<E = hyper::Error>(E);

impl<E: std::borrow::Borrow<hyper::Error>> Display for LogSafeHyperError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self.0.borrow(), f)
    }
}

/// [`hyper::Error`]'s [`Display`] impl doesn't contain any user data, just a
/// description of the kind of error.
impl LogSafeDisplay for LogSafeHyperError {}

fn make_connect_request(
    (tcp_host, port): (Host<&str>, NonZeroU16),
    authorization: Option<&HttpProxyAuth>,
) -> Result<http::Request<Empty<Bytes>>, ConnectError> {
    let authority = Authority::from_maybe_shared(format!("{tcp_host}:{port}"))
        .map_err(ConnectError::InvalidUri)?;

    let uri = Uri::builder()
        .authority(authority)
        .build()
        .expect("already validated authority");

    let http_host = format!("{tcp_host}:{port}");
    let mut http_request = http::Request::connect(uri).header(http::header::HOST, http_host);

    if let Some(auth) = authorization {
        let (name, value) = auth.as_header();
        http_request = http_request.header(name, value);
    }

    http_request
        .body(Empty::new())
        .map_err(ConnectError::InvalidRequest)
}

impl AsHttpHeader for HttpProxyAuth {
    const HEADER_NAME: http::HeaderName = http::header::PROXY_AUTHORIZATION;

    fn header_value(&self) -> http::HeaderValue {
        let Self { username, password } = self;
        crate::utils::basic_authorization(username, password)
    }
}

impl AsyncRead for HttpProxyStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpProxyStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.project().inner.poll_shutdown(cx)
    }
}

impl Connection for HttpProxyStream {
    fn transport_info(&self) -> TransportInfo {
        self.info.clone()
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use either::Either;
    use futures_util::future::BoxFuture;
    use futures_util::FutureExt;
    use http::method::Method;
    use http::{HeaderMap, HeaderValue, StatusCode};
    use http_body_util::Empty;
    use hyper::body::Incoming;
    use hyper::service::Service;
    use hyper::{Request, Response};
    use nonzero_ext::nonzero;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::mpsc;

    use super::*;
    use crate::route::TcpRoute;
    use crate::tcp_ssl::proxy::testutil::TcpServer;

    /// [`hyper::service::HttpService`] that handles [`http::Method::CONNECT`]s.
    #[derive(Clone)]
    struct ProxyService {
        upgrades_tx: mpsc::UnboundedSender<UpgradeOutcome>,
        expected_auth: Option<HttpProxyAuth>,
    }

    struct UpgradeOutcome {
        authority: Authority,
        fake_server_stream: DuplexStream,
        headers: HeaderMap,
    }

    impl Service<Request<Incoming>> for ProxyService {
        type Response = Response<Empty<Bytes>>;

        type Error = hyper::Error;

        type Future = BoxFuture<'static, hyper::Result<Self::Response>>;

        fn call(&self, mut req: Request<Incoming>) -> Self::Future {
            log::info!("got incoming request {req:?}");
            let (server_io, mut client_io) = tokio::io::duplex(1024);
            let Self {
                upgrades_tx,
                expected_auth,
            } = self.clone();
            async move {
                let mut res = Response::new(Empty::new());
                if req.method() != Method::CONNECT {
                    log::error!("method is not CONNECT");
                    *res.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(res);
                }
                let uri = req.uri();
                if let Some(path) = uri.path_and_query() {
                    log::error!("path was unexpectedly supplied: {path}");
                    *res.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(res);
                };
                let Some(authority) = uri.authority().cloned() else {
                    log::error!("no authority");
                    *res.status_mut() = StatusCode::BAD_REQUEST;
                    return Ok(res);
                };

                let expected_auth = expected_auth.as_ref().map(|h| h.as_header().1);
                let auth = req.headers().get(HttpProxyAuth::HEADER_NAME);
                if auth != expected_auth.as_ref() {
                    log::error!("auth header mismatch; expected {expected_auth:?}, got {auth:?}");
                    *res.status_mut() = StatusCode::UNAUTHORIZED;
                    return Ok(res);
                }

                let upgraded = UpgradeOutcome {
                    fake_server_stream: server_io,
                    authority,
                    headers: req.headers().clone(),
                };

                tokio::task::spawn(async move {
                    log::debug!("started upgrade copy task");
                    match hyper::upgrade::on(&mut req).await {
                        Ok(upgraded) => {
                            let _ignore_error = tokio::io::copy_bidirectional(
                                &mut TokioIo::new(upgraded),
                                &mut client_io,
                            )
                            .await;
                        }
                        Err(e) => eprintln!("upgrade error: {}", e),
                    }
                });
                upgrades_tx.send(upgraded).expect("not hung up on");
                Ok(res)
            }
            .boxed()
        }
    }

    fn spawn_localhost_proxy(service: ProxyService) -> TcpRoute<IpAddr> {
        let tcp_server = TcpServer::bind_localhost();
        let server_addr = tcp_server.listen_addr;

        let _task_handle = tokio::spawn(async move {
            loop {
                let (stream, _info) = tcp_server.accept().await;
                hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), &service)
                    .with_upgrades()
                    .await
                    .expect("handles connection")
            }
        });

        server_addr.try_into().unwrap()
    }

    const TARGET_PORT: NonZeroU16 = nonzero!(1234u16);
    const TARGET_HOST: &str = "fake-target.example.com";
    const EXPECTED_AUTHORITY: &str = "fake-target.example.com:1234";
    const USERNAME: &str = "fake-username";
    const PASSWORD: &str = "fake-password";

    #[test_log::test(tokio::test)]
    async fn successful_connect() {
        let authorization = Some(HttpProxyAuth {
            username: USERNAME.to_owned(),
            password: PASSWORD.to_owned(),
        });

        let (proxy_upstream_tx, mut proxy_upstream_rx) = mpsc::unbounded_channel();

        let route_to_proxy = spawn_localhost_proxy(ProxyService {
            upgrades_tx: proxy_upstream_tx,
            expected_auth: authorization.clone(),
        });

        let route = HttpsProxyRoute {
            fragment: HttpProxyRouteFragment {
                target_host: ProxyTarget::ResolvedRemotely {
                    name: TARGET_HOST.into(),
                },
                target_port: TARGET_PORT,
                authorization,
            },
            inner: Either::Right(route_to_proxy),
        };

        let mut client_stream = super::super::StatelessProxied
            .connect(route, "test".into())
            .await
            .expect("can connect");

        let UpgradeOutcome {
            authority,
            mut fake_server_stream,
            headers,
        } = proxy_upstream_rx
            .recv()
            .await
            .expect("server still running");

        let expected_headers = HeaderMap::from_iter([
            (
                http::header::HOST,
                HeaderValue::from_static(EXPECTED_AUTHORITY),
            ),
            (
                http::header::PROXY_AUTHORIZATION,
                crate::utils::basic_authorization(USERNAME, PASSWORD),
            ),
        ]);

        assert_eq!(authority, EXPECTED_AUTHORITY);
        assert_eq!(headers, expected_headers);

        const SEND_TO_SERVER: &str = "message from the client";
        const SEND_TO_CLIENT: &str = "sent from the fake server";

        let (received_by_client, received_by_server) = async {
            tokio::try_join!(
                fake_server_stream.write_all(SEND_TO_CLIENT.as_bytes()),
                client_stream.write_all(SEND_TO_SERVER.as_bytes())
            )
            .expect("can write");

            let mut from_server = [0; SEND_TO_CLIENT.len()];
            let mut from_client = [0; SEND_TO_SERVER.len()];
            tokio::try_join!(
                client_stream.read_exact(&mut from_server),
                fake_server_stream.read_exact(&mut from_client)
            )
            .expect("can read");
            (from_server, from_client)
        }
        .await;

        assert_eq!(received_by_client, SEND_TO_CLIENT.as_bytes());
        assert_eq!(received_by_server, SEND_TO_SERVER.as_bytes());
    }

    #[test_log::test(tokio::test)]
    async fn authorization_rejected() {
        let authorization = Some(HttpProxyAuth {
            username: USERNAME.to_owned(),
            password: PASSWORD.to_owned(),
        });

        let (proxy_upstream_tx, _proxy_upstream_rx) = mpsc::unbounded_channel();

        let route_to_proxy = spawn_localhost_proxy(ProxyService {
            upgrades_tx: proxy_upstream_tx,
            expected_auth: authorization.clone(),
        });

        let route = HttpsProxyRoute {
            fragment: HttpProxyRouteFragment {
                target_host: ProxyTarget::ResolvedRemotely {
                    name: TARGET_HOST.into(),
                },
                target_port: TARGET_PORT,
                authorization: Some(HttpProxyAuth {
                    username: "wrong-user".into(),
                    password: "wrong-pass".into(),
                }),
            },
            inner: Either::Right(route_to_proxy),
        };

        let connect_result = super::super::StatelessProxied
            .connect(route, "test".into())
            .await;

        assert_matches!(connect_result, Err(TransportConnectError::ProxyProtocol));
    }
}
