//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::Bytes;
use futures_util::{Sink, Stream};
use http::{HeaderName, HeaderValue};
use libsignal_core::LogSafeDisplay as _;
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tungstenite::Message;

use crate::errors::TransportConnectError;
use crate::route::{
    ComposedConnector, Connector, ConnectorExt as _, DEFAULT_HTTPS_PORT, ReflectorProxyRoute,
};
use crate::ws::error::WebSocketConnectError;
use crate::{Connection, ws};

pub(crate) const LONG_FULL_CONNECT_THRESHOLD: Duration = super::LONG_TCP_HANDSHAKE_THRESHOLD
    .saturating_add(super::LONG_TLS_HANDSHAKE_THRESHOLD)
    .saturating_add(Duration::from_secs(3));

const X_SIGNAL_HOST_HEADER: HeaderName = HeaderName::from_static("x-signal-host");

/// Cap per outbound `Message::Binary`; comfortably fits one TLS record.
const MAX_OUTBOUND_FRAME_SIZE: usize = 64 * 1024;
/// Outbound buffer cap; once exceeded, tungstenite returns `WriteBufferFull`.
const MAX_OUTBOUND_BUFFER_SIZE: usize = 4 * MAX_OUTBOUND_FRAME_SIZE;

fn ws_config() -> tungstenite::protocol::WebSocketConfig {
    let mut config = tungstenite::protocol::WebSocketConfig::default();
    config.write_buffer_size = MAX_OUTBOUND_FRAME_SIZE;
    config.max_write_buffer_size = MAX_OUTBOUND_BUFFER_SIZE;
    config
}

type StatelessTcpConnector = crate::tcp_ssl::StatelessTcp;
type StatelessTlsConnector = ComposedConnector<crate::tcp_ssl::StatelessTls, StatelessTcpConnector>;
type ReflectorConnector = ComposedConnector<ws::WithoutResponseHeaders, StatelessTlsConnector>;

#[derive(Debug)]
#[pin_project(project = ReflectorStreamProj)]
pub struct ReflectorStream {
    #[pin]
    inner: tokio_tungstenite::WebSocketStream<Box<dyn ws::WebSocketTransportStream>>,
    pending_read: Bytes,
    // Set on I/O error: a Sink failure can drop already-accepted writes.
    broken: bool,
}

impl ReflectorStreamProj<'_> {
    fn poison_on_err<T>(&mut self, result: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if matches!(&result, Poll::Ready(Err(_))) {
            *self.broken = true;
        }
        result
    }
}

impl ReflectorStream {
    fn new(
        inner: tokio_tungstenite::WebSocketStream<Box<dyn ws::WebSocketTransportStream>>,
    ) -> Self {
        Self {
            inner,
            pending_read: Bytes::new(),
            broken: false,
        }
    }
}

fn websocket_error_to_io(error: tungstenite::Error) -> io::Error {
    match error {
        tungstenite::Error::Io(error) => error,
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => {
            io::Error::new(io::ErrorKind::UnexpectedEof, error)
        }
        other => io::Error::other(other),
    }
}

impl AsyncRead for ReflectorStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut this = self.project();
        if *this.broken {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        loop {
            if !this.pending_read.is_empty() {
                let to_copy = this.pending_read.len().min(buf.remaining());
                buf.put_slice(&this.pending_read.split_to(to_copy));
                return Poll::Ready(Ok(()));
            }

            match ready!(this.inner.as_mut().poll_next(cx)) {
                Some(Ok(Message::Binary(binary))) => {
                    *this.pending_read = binary;
                }
                Some(Ok(Message::Text(_))) => {
                    *this.broken = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "reflector tunnel received text frame",
                    )));
                }
                Some(Ok(Message::Close(_))) | None => return Poll::Ready(Ok(())),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Frame(_))) => {
                    unreachable!("Message::Frame is never returned for a read")
                }
                Some(Err(error)) => {
                    *this.broken = true;
                    return Poll::Ready(Err(websocket_error_to_io(error)));
                }
            }
        }
    }
}

impl AsyncWrite for ReflectorStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut this = self.project();
        if *this.broken {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        match this.inner.as_mut().poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                *this.broken = true;
                return Poll::Ready(Err(websocket_error_to_io(e)));
            }
            Poll::Ready(Ok(())) => {}
        }
        let chunk = &buf[..buf.len().min(MAX_OUTBOUND_FRAME_SIZE)];
        if let Err(e) = this
            .inner
            .as_mut()
            .start_send(Message::Binary(Bytes::copy_from_slice(chunk)))
        {
            *this.broken = true;
            return Poll::Ready(Err(websocket_error_to_io(e)));
        }
        Poll::Ready(Ok(chunk.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let mut this = self.project();
        if *this.broken {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let result = this
            .inner
            .as_mut()
            .poll_flush(cx)
            .map_err(websocket_error_to_io);
        this.poison_on_err(result)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let mut this = self.project();
        if *this.broken {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let result = this
            .inner
            .as_mut()
            .poll_close(cx)
            .map_err(websocket_error_to_io);
        this.poison_on_err(result)
    }
}

impl Connection for ReflectorStream {
    fn transport_info(&self) -> crate::TransportInfo {
        self.inner.transport_info()
    }
}

impl Connector<Box<ReflectorProxyRoute<IpAddr>>, ()> for super::StatelessProxied {
    type Connection = ReflectorStream;

    type Error = TransportConnectError;

    async fn connect_over(
        &self,
        (): (),
        route: Box<ReflectorProxyRoute<IpAddr>>,
        log_tag: &str,
    ) -> Result<Self::Connection, Self::Error> {
        let ReflectorProxyRoute {
            mut outer,
            target_host,
            target_port,
        } = *route;

        outer.fragment.ws_config = ws_config();
        let host_header = if target_port == DEFAULT_HTTPS_PORT {
            target_host.to_string()
        } else {
            format!("{target_host}:{target_port}")
        };
        outer.fragment.headers.insert(
            X_SIGNAL_HOST_HEADER,
            HeaderValue::from_str(&host_header)
                .map_err(|_| TransportConnectError::InvalidConfiguration)?,
        );

        let connector = ReflectorConnector::new(
            ws::WithoutResponseHeaders::new(),
            StatelessTlsConnector::default(),
        );
        let https_route = &outer.inner;
        let http_fragment = &https_route.fragment;
        let proxy_name = http_fragment.front_name.unwrap_or("unknown");
        log::info!("[{log_tag}] attempting connection over reflector proxy ({proxy_name})");
        match connector.connect(outer, log_tag).await {
            Ok(websocket) => Ok(ReflectorStream::new(websocket)),
            Err(WebSocketConnectError::Transport(error)) => Err(error),
            Err(WebSocketConnectError::WebSocketError(error)) => {
                log::info!(
                    "[{log_tag}] failed to connect via reflector proxy: {}",
                    error.log_safe_display()
                );
                Err(TransportConnectError::ProxyProtocol)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::net::SocketAddr;

    use assert_matches::assert_matches;
    use futures_util::{SinkExt as _, StreamExt as _};
    use http::uri::PathAndQuery;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
    use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

    use super::*;
    use crate::certs::RootCertificates;
    use crate::host::Host;
    use crate::route::{
        HttpRouteFragment, HttpVersion, HttpsTlsRoute, TcpRoute, TlsRoute, TlsRouteFragment,
        WebSocketRoute, WebSocketRouteFragment,
    };
    use crate::tcp_ssl::proxy::testutil::{
        PROXY_CERTIFICATE, PROXY_HOSTNAME, TcpServer, TlsServer,
    };
    use crate::{Alpn, OverrideNagleAlgorithm};

    const TARGET_HOST: &str = "chat.signal.org";
    const EXPECTED_PATH: &str = "/tls-tunnel";

    fn test_route(server_addr: SocketAddr) -> Box<ReflectorProxyRoute<IpAddr>> {
        Box::new(ReflectorProxyRoute {
            outer: WebSocketRoute {
                fragment: WebSocketRouteFragment {
                    ws_config: WebSocketConfig::default(),
                    endpoint: PathAndQuery::from_static(EXPECTED_PATH),
                    headers: Default::default(),
                },
                inner: HttpsTlsRoute {
                    fragment: HttpRouteFragment {
                        host_header: PROXY_HOSTNAME.into(),
                        path_prefix: "".into(),
                        http_version: Some(HttpVersion::Http1_1),
                        front_name: Some("reflector-test"),
                    },
                    inner: TlsRoute {
                        fragment: TlsRouteFragment {
                            root_certs: RootCertificates::FromDer(Cow::Borrowed(
                                PROXY_CERTIFICATE.cert.der(),
                            )),
                            sni: Host::Domain(PROXY_HOSTNAME.into()),
                            alpn: Some(Alpn::Http1_1),
                            min_protocol_version: None,
                        },
                        inner: TcpRoute {
                            address: server_addr.ip(),
                            port: server_addr.port().try_into().expect("valid port"),
                            override_nagle_algorithm: OverrideNagleAlgorithm::UseSystemDefault,
                        },
                    },
                },
            },
            target_host: TARGET_HOST.into(),
            target_port: DEFAULT_HTTPS_PORT,
        })
    }

    #[test_log::test(tokio::test)]
    async fn raw_reflector_success_test() {
        let tls_server = TlsServer::new(TcpServer::bind_localhost(), &PROXY_CERTIFICATE);
        let server_addr = tls_server.tcp.listen_addr;
        let (request_tx, mut request_rx) = mpsc::unbounded_channel();

        let server_task = tokio::spawn(async move {
            let (tls_stream, _remote_addr) = tls_server.accept().await;
            let mut websocket = tokio_tungstenite::accept_hdr_async(
                tls_stream,
                // Tungstenite's handshake callback type; not our code.
                #[allow(clippy::result_large_err)]
                move |request: &Request, response: Response| {
                    request_tx
                        .send((
                            request.uri().path().to_owned(),
                            request.headers().get(http::header::HOST).cloned(),
                            request.headers().get(&X_SIGNAL_HOST_HEADER).cloned(),
                        ))
                        .expect("receiver still alive");
                    Ok(response)
                },
            )
            .await
            .expect("can upgrade");

            websocket
                .send(Message::Binary(Bytes::from_static(b"from reflector")))
                .await
                .expect("can send");

            let received = websocket
                .next()
                .await
                .expect("client message")
                .expect("websocket ok");
            assert_eq!(
                received,
                Message::Binary(Bytes::from_static(b"from client"))
            );
        });

        let mut stream = super::super::StatelessProxied
            .connect(test_route(server_addr), "test")
            .await
            .expect("can connect");
        stream.write_all(b"from client").await.expect("can write");
        stream.flush().await.expect("can flush");

        let mut received = [0; "from reflector".len()];
        stream
            .read_exact(&mut received)
            .await
            .expect("can read tunneled bytes");
        assert_eq!(&received, b"from reflector");

        let (path, host, x_signal_host) = request_rx.recv().await.expect("captured request");
        assert_eq!(path, EXPECTED_PATH);
        assert_eq!(host, Some(HeaderValue::from_static(PROXY_HOSTNAME)));
        assert_eq!(x_signal_host, Some(HeaderValue::from_static(TARGET_HOST)));

        tokio::time::timeout(Duration::from_secs(1), server_task)
            .await
            .expect("server task finished within 1s")
            .expect("server task succeeded");
    }

    #[test_log::test(tokio::test)]
    async fn upgrade_failure_maps_to_proxy_protocol() {
        let tls_server = TlsServer::new(TcpServer::bind_localhost(), &PROXY_CERTIFICATE);
        let server_addr = tls_server.tcp.listen_addr;

        let server_task = tokio::spawn(async move {
            let (mut tls_stream, _remote_addr) = tls_server.accept().await;
            tls_stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("can write");
            tls_stream.flush().await.expect("can flush");
        });

        let result = super::super::StatelessProxied
            .connect(test_route(server_addr), "test")
            .await;
        assert_matches!(result, Err(TransportConnectError::ProxyProtocol));

        tokio::time::timeout(Duration::from_secs(1), server_task)
            .await
            .expect("server task finished within 1s")
            .expect("server task succeeded");
    }

    #[tokio::test]
    async fn text_frame_rejected() {
        let (mut server, client) = crate::ws::testutil::fake_websocket().await;
        let mut stream = ReflectorStream::new(client);

        server
            .send(Message::Text("unexpected".into()))
            .await
            .expect("can send");

        let mut buf = [0; 16];
        let error = stream
            .read(&mut buf)
            .await
            .expect_err("text frames are rejected");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn writes_larger_than_frame_cap_are_chunked() {
        let (mut server, client) = crate::ws::testutil::fake_websocket().await;
        let mut stream = ReflectorStream::new(client);

        let server_task =
            tokio::spawn(async move { server.next().await.expect("msg").expect("ok") });

        let payload = vec![0xAA; MAX_OUTBOUND_FRAME_SIZE + 100];
        let n = stream.write(&payload).await.expect("can write");
        stream.flush().await.expect("can flush");

        assert_eq!(n, MAX_OUTBOUND_FRAME_SIZE);
        let msg = server_task.await.expect("task ok");
        let bytes = assert_matches!(msg, Message::Binary(bytes) => bytes);
        assert_eq!(bytes.len(), MAX_OUTBOUND_FRAME_SIZE);
    }

    #[tokio::test]
    async fn stream_is_poisoned_after_error() {
        let (mut server, client) = crate::ws::testutil::fake_websocket().await;
        let mut stream = ReflectorStream::new(client);

        server
            .send(Message::Text("unexpected".into()))
            .await
            .expect("can send");

        let mut buf = [0; 16];
        let initial = stream
            .read(&mut buf)
            .await
            .expect_err("text frames are rejected");
        assert_eq!(initial.kind(), io::ErrorKind::InvalidData);

        assert_eq!(
            stream
                .read(&mut buf)
                .await
                .expect_err("read should short-circuit")
                .kind(),
            io::ErrorKind::BrokenPipe,
        );
        assert_eq!(
            stream
                .write(b"x")
                .await
                .expect_err("write should short-circuit")
                .kind(),
            io::ErrorKind::BrokenPipe,
        );
        assert_eq!(
            stream
                .flush()
                .await
                .expect_err("flush should short-circuit")
                .kind(),
            io::ErrorKind::BrokenPipe,
        );
    }
}
