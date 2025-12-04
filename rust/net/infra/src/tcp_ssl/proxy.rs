//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::IpAddr;

use futures_util::TryFutureExt;
use tokio::net::TcpStream;
use tokio_util::either::Either;

use crate::Connection;
use crate::errors::TransportConnectError;
use crate::route::{
    ConnectionProxyRoute, Connector, ConnectorExt as _, LoggingConnector, TlsRoute,
};

pub mod https;
pub mod socks;

mod stream;
pub use stream::ProxyStream;

use super::{LONG_TCP_HANDSHAKE_THRESHOLD, LONG_TLS_HANDSHAKE_THRESHOLD};

/// Stateless [`Connector`] impl for [`ConnectionProxyRoute`].
#[derive(Debug, Default)]
pub struct StatelessProxied;

impl Connector<ConnectionProxyRoute<IpAddr>, ()> for StatelessProxied {
    type Connection = ProxyStream;

    type Error = TransportConnectError;

    async fn connect_over(
        &self,
        (): (),
        route: ConnectionProxyRoute<IpAddr>,
        log_tag: &str,
    ) -> Result<Self::Connection, Self::Error> {
        match route {
            ConnectionProxyRoute::Tls { proxy } => {
                let TlsRoute {
                    fragment: tls_fragment,
                    inner,
                } = proxy;

                let tcp = LoggingConnector::new(
                    super::StatelessTcp,
                    LONG_TCP_HANDSHAKE_THRESHOLD,
                    "Proxy-TCP",
                )
                .connect(inner, log_tag)
                .await?;
                LoggingConnector::new(
                    super::StatelessTls,
                    LONG_TLS_HANDSHAKE_THRESHOLD,
                    "Proxy-TLS",
                )
                .connect_over(tcp, tls_fragment, log_tag)
                .await
                .map(Into::into)
            }
            #[cfg(feature = "dev-util")]
            ConnectionProxyRoute::Tcp { proxy } => {
                let connector = LoggingConnector::new(
                    super::StatelessTcp,
                    LONG_TCP_HANDSHAKE_THRESHOLD,
                    "Proxy-TCP",
                );
                match connector.connect(proxy, log_tag).await {
                    Ok(connection) => Ok(connection.into()),
                    Err(_io_error) => Err(TransportConnectError::TcpConnectionFailed),
                }
            }
            ConnectionProxyRoute::Socks(route) => {
                LoggingConnector::new(
                    self,
                    socks::LONG_FULL_CONNECT_THRESHOLD,
                    "Proxy-TCP+SOCKS+TLS",
                )
                .connect(route, log_tag)
                .map_ok(Into::into)
                .await
            }
            ConnectionProxyRoute::Https(route) => {
                LoggingConnector::new(
                    self,
                    https::LONG_FULL_CONNECT_THRESHOLD,
                    "Proxy-TCP+TLS+HTTP+TLS",
                )
                .connect(route, log_tag)
                .map_ok(Into::into)
                .await
            }
        }
    }
}

impl<L: Connection, R: Connection> Connection for Either<L, R> {
    fn transport_info(&self) -> crate::TransportInfo {
        match self {
            Self::Left(l) => l.transport_info(),
            Self::Right(r) => r.transport_info(),
        }
    }
}

impl Connection for TcpStream {
    fn transport_info(&self) -> crate::TransportInfo {
        let local_addr = self.local_addr().expect("has local addr");
        let remote_addr = self.peer_addr().expect("has remote addr");
        crate::TransportInfo {
            local_addr,
            remote_addr,
        }
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::future::Future;
    use std::net::{Ipv6Addr, SocketAddr};
    use std::sync::LazyLock;

    use assert_matches::assert_matches;
    use boring_signal::pkey::PKey;
    use boring_signal::ssl::{SslAcceptor, SslMethod};
    use boring_signal::x509::X509;
    use futures_util::{Stream, StreamExt as _, pin_mut};
    use libsignal_core::try_scoped;
    use rcgen::CertifiedKey;
    use tls_parser::{ClientHello, TlsExtension, TlsMessage, TlsMessageHandshake, TlsPlaintext};
    use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufStream};

    pub(crate) const PROXY_HOSTNAME: &str = "test-proxy.signal.org.local";

    pub(crate) static PROXY_CERTIFICATE: LazyLock<CertifiedKey> = LazyLock::new(|| {
        rcgen::generate_simple_self_signed([PROXY_HOSTNAME.to_string()]).expect("can generate")
    });

    struct ProxyServer<S> {
        incoming_connections_stream: S,
        upstream_addr: SocketAddr,
    }

    impl<S: Stream<Item: AsyncRead + AsyncWrite>> ProxyServer<S> {
        async fn proxy(self) {
            let Self {
                incoming_connections_stream,
                upstream_addr,
            } = self;
            pin_mut!(incoming_connections_stream);

            loop {
                let accepted = incoming_connections_stream
                    .next()
                    .await
                    .expect("incoming connection");
                pin_mut!(accepted);

                // Now connect to the upstream and then proxy for the life of the connection.
                let mut upstream_stream = tokio::net::TcpStream::connect(upstream_addr)
                    .await
                    .expect("can connect to upstream");
                tokio::io::copy_bidirectional(&mut accepted, &mut upstream_stream)
                    .await
                    .expect("can proxy");
            }
        }
    }

    pub(super) struct TcpServer {
        tcp_listener: tokio::net::TcpListener,
        pub(super) listen_addr: SocketAddr,
    }

    impl TcpServer {
        pub(super) fn accept(
            &self,
        ) -> impl Future<Output = (tokio::net::TcpStream, SocketAddr)> + Unpin + '_ {
            std::future::poll_fn(move |cx| {
                self.tcp_listener
                    .poll_accept(cx)
                    .map(|r| r.expect("incoming connection"))
            })
        }

        pub(crate) fn into_listener(self) -> tokio::net::TcpListener {
            self.tcp_listener
        }
    }

    pub(super) struct TlsServer {
        ssl_acceptor: SslAcceptor,
        pub(super) tcp: TcpServer,
    }

    impl TcpServer {
        pub(super) fn bind_localhost() -> Self {
            let listener = std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).expect("can bind");
            listener.set_nonblocking(true).expect("can set nonblocking");
            let listen_addr = listener.local_addr().expect("is bound to local addr");
            let tcp_listener =
                tokio::net::TcpListener::from_std(listener).expect("can use std socket");

            Self {
                listen_addr,
                tcp_listener,
            }
        }
    }

    impl TlsServer {
        pub(super) fn new(server: TcpServer, certificate: &CertifiedKey) -> Self {
            let ssl_acceptor = try_scoped(|| {
                let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
                builder.set_certificate(X509::from_der(certificate.cert.der())?.as_ref())?;
                builder.set_private_key(
                    PKey::private_key_from_der(certificate.key_pair.serialized_der())?.as_ref(),
                )?;
                // If the cert can be loaded, build the thing.
                builder.check_private_key().map(|()| builder.build())
            })
            .expect("can configure acceptor");

            Self {
                ssl_acceptor,
                tcp: server,
            }
        }

        pub(super) async fn accept(
            &self,
        ) -> (impl AsyncRead + AsyncWrite + Unpin + use<>, SocketAddr) {
            let (tcp_stream, remote_addr) = self.tcp.accept().await;
            let ssl_stream = tokio_boring_signal::accept(&self.ssl_acceptor, tcp_stream)
                .await
                .expect("handshake successful");
            (ssl_stream, remote_addr)
        }
    }

    /// Starts a TLS server that proxies TLS connections to an upstream server.
    ///
    /// Proxies TLS connections with `upstream_sni` to `upstream_addr`.
    pub(super) fn localhost_tls_proxy(
        upstream_sni: &'static str,
        upstream_addr: SocketAddr,
    ) -> (SocketAddr, impl Future<Output = ()>) {
        let tcp_server = TcpServer::bind_localhost();
        let listen_addr = tcp_server.listen_addr;
        let tls_server = TlsServer::new(tcp_server, &PROXY_CERTIFICATE);

        let accepts = futures_util::stream::unfold(tls_server, move |tls_server| async move {
            let (ssl_stream, _remote_addr) = tls_server.accept().await;

            let (sni_names, ssl_stream) = parse_sni_from_stream(ssl_stream).await;
            assert_eq!(sni_names, &[upstream_sni]);
            Some((ssl_stream, tls_server))
        });
        let proxy = ProxyServer {
            incoming_connections_stream: accepts,
            upstream_addr,
        }
        .proxy();

        (listen_addr, proxy)
    }

    /// Starts a TCP server that proxies connections to an upstream server.
    ///
    /// Proxies TCP connections to `upstream_addr`.
    #[cfg(feature = "dev-util")]
    pub(super) fn localhost_tcp_proxy(
        upstream_addr: SocketAddr,
    ) -> (SocketAddr, impl Future<Output = ()>) {
        let TcpServer {
            tcp_listener,
            listen_addr,
        } = TcpServer::bind_localhost();
        let accepts = futures_util::stream::unfold(tcp_listener, move |tcp_listener| async move {
            let (tcp_stream, _remote_addr) =
                tcp_listener.accept().await.expect("incoming connection");

            Some((tcp_stream, tcp_listener))
        });
        let proxy = ProxyServer {
            incoming_connections_stream: accepts,
            upstream_addr,
        }
        .proxy();

        (listen_addr, proxy)
    }

    /// Read SNI names from TCP handshake on a stream.
    ///
    /// Consumes the stream and returns a new one with the same contents.
    pub(super) async fn parse_sni_from_stream<S: AsyncRead + AsyncWrite + Unpin>(
        stream: S,
    ) -> (Vec<String>, BufStream<S>) {
        /// Minimum acceptable size for a TCP segment.
        ///
        /// The first TLS frame sent by the client should fit within this.
        const TCP_MIN_MSS: usize = 576;

        let mut stream = tokio::io::BufStream::with_capacity(TCP_MIN_MSS, TCP_MIN_MSS, stream);

        let first_record = loop {
            // We're intentionally reading from the buffer without marking the
            // bytes as consumed so that when the stream is passed back to the
            // caller they can read them too.
            let buffer = stream.fill_buf().await.expect("can read");
            match tls_parser::parse_tls_plaintext(buffer) {
                Ok((_, record)) => break record,
                Err(tls_parser::Err::Incomplete(_)) => continue,
                Err(e) => panic!("failed to parse TLS: {e}"),
            }
        };

        let TlsPlaintext { hdr: _, msg } = first_record;
        let msg = msg.first().expect("nonempty messages");
        let client_hello = assert_matches!(
            msg,
            TlsMessage::Handshake(TlsMessageHandshake::ClientHello(hello)) => hello
        );
        let (_, client_hello_extensions) = tls_parser::parse_tls_client_hello_extensions(
            client_hello.ext().expect("has extensions"),
        )
        .expect("can parse extensions");
        let sni = client_hello_extensions
            .into_iter()
            .find_map(|ex| match ex {
                TlsExtension::SNI(sni) => Some(sni),
                _ => None,
            })
            .expect("has SNI extension");
        let names = sni
            .into_iter()
            .map(|(_sni_type, name)| String::from_utf8(Vec::from(name)).expect("SNI name is UTF-8"))
            .collect();

        (names, stream)
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;

    use crate::certs::RootCertificates;
    use crate::host::Host;
    use crate::route::{
        ConnectionProxyRoute, Connector as _, ConnectorExt as _, TcpRoute, TlsRoute,
        TlsRouteFragment,
    };
    use crate::tcp_ssl::StatelessTls;
    use crate::tcp_ssl::proxy::testutil::{PROXY_CERTIFICATE, PROXY_HOSTNAME, localhost_tls_proxy};
    use crate::tcp_ssl::testutil::{
        SERVER_CERTIFICATE, SERVER_HOSTNAME, make_http_request_response_over,
        simple_localhost_https_server,
    };
    use crate::{Alpn, OverrideNagleAlgorithm};

    #[tokio::test]
    async fn connect_through_proxy() {
        let (addr, server) = simple_localhost_https_server();
        let _server_handle = tokio::spawn(server);

        let (proxy_addr, proxy) = localhost_tls_proxy(SERVER_HOSTNAME, addr);
        let _proxy_handle = tokio::spawn(proxy);

        // Ensure that the proxy is doing the right thing
        let route = ConnectionProxyRoute::Tls {
            proxy: TlsRoute {
                fragment: TlsRouteFragment {
                    root_certs: RootCertificates::FromDer(Cow::Borrowed(
                        PROXY_CERTIFICATE.cert.der(),
                    )),
                    sni: Host::Domain(PROXY_HOSTNAME.into()),
                    alpn: None,
                    min_protocol_version: None,
                },
                inner: TcpRoute {
                    address: proxy_addr.ip(),
                    port: proxy_addr.port().try_into().unwrap(),
                    override_nagle_algorithm: OverrideNagleAlgorithm::UseSystemDefault,
                },
            },
        };

        let stream = super::StatelessProxied
            .connect(route, "tls proxy test")
            .await
            .expect("can connect");

        // The server speaks HTTPS so we need to establish a TLS stream over our
        // proxied stream.
        let stream = StatelessTls
            .connect_over(
                stream,
                TlsRouteFragment {
                    root_certs: RootCertificates::FromDer(Cow::Borrowed(
                        SERVER_CERTIFICATE.cert.der(),
                    )),
                    sni: Host::Domain(SERVER_HOSTNAME.into()),
                    alpn: Some(Alpn::Http1_1),
                    min_protocol_version: None,
                },
                "tcp proxy test",
            )
            .await
            .expect("can connect");

        make_http_request_response_over(stream)
            .await
            .expect("success");
    }

    #[cfg(feature = "dev-util")]
    #[tokio::test]
    async fn connect_through_unencrypted_proxy() {
        let (addr, server) = simple_localhost_https_server();
        let _server_handle = tokio::spawn(server);

        let (proxy_addr, proxy) = super::testutil::localhost_tcp_proxy(addr);
        let _proxy_handle = tokio::spawn(proxy);

        // Ensure that the proxy is doing the right thing
        let route = ConnectionProxyRoute::Tcp {
            proxy: TcpRoute {
                address: proxy_addr.ip(),
                port: proxy_addr.port().try_into().unwrap(),
                override_nagle_algorithm: OverrideNagleAlgorithm::UseSystemDefault,
            },
        };

        let stream = super::StatelessProxied
            .connect(route, "tcp proxy test")
            .await
            .expect("can connect");

        // The server speaks HTTPS so we need to establish a TLS stream over our
        // proxied stream.
        let stream = StatelessTls
            .connect_over(
                stream,
                TlsRouteFragment {
                    root_certs: RootCertificates::FromDer(Cow::Borrowed(
                        SERVER_CERTIFICATE.cert.der(),
                    )),
                    sni: Host::Domain(SERVER_HOSTNAME.into()),
                    alpn: Some(Alpn::Http1_1),
                    min_protocol_version: None,
                },
                "tcp proxy test",
            )
            .await
            .expect("can connect");

        make_http_request_response_over(stream)
            .await
            .expect("success");
    }
}
