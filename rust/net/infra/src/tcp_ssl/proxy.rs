//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::IpAddr;
use std::sync::Arc;

use futures_util::TryFutureExt;
use tokio::net::TcpStream;
use tokio_util::either::Either;

use crate::errors::TransportConnectError;
use crate::route::{ConnectionProxyRoute, Connector, ConnectorExt as _, TlsRoute};
use crate::{Connection, IpType};

pub mod https;
pub mod socks;
pub mod tls;

mod stream;
pub use stream::ProxyStream;

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
        log_tag: Arc<str>,
    ) -> Result<Self::Connection, Self::Error> {
        match route {
            ConnectionProxyRoute::Tls { proxy } => {
                let TlsRoute {
                    fragment: tls_fragment,
                    inner,
                } = proxy;

                let connector = super::StatelessDirect;

                let tcp = connector.connect(inner, log_tag.clone()).await?;
                connector
                    .connect_over(tcp, tls_fragment, log_tag)
                    .await
                    .map(Into::into)
            }
            ConnectionProxyRoute::Tcp { proxy } => {
                let connector = super::StatelessDirect;
                match connector.connect(proxy, log_tag).await {
                    Ok(connection) => Ok(connection.into()),
                    Err(_io_error) => Err(TransportConnectError::TcpConnectionFailed),
                }
            }
            ConnectionProxyRoute::Socks(route) => {
                self.connect(route, log_tag).map_ok(Into::into).await
            }
            ConnectionProxyRoute::Https(route) => {
                self.connect(route, log_tag).map_ok(Into::into).await
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
        crate::TransportInfo {
            ip_version: IpType::from(&local_addr.ip()),
            local_port: local_addr.port(),
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
    use futures_util::{pin_mut, Stream, StreamExt as _};
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
            // TODO(https://github.com/rust-lang/rust/issues/31436): use a `try`
            // block instead of immediately-invoked closure.
            let ssl_acceptor = (|| {
                let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
                builder.set_certificate(X509::from_der(certificate.cert.der())?.as_ref())?;
                builder.set_private_key(
                    PKey::private_key_from_der(certificate.key_pair.serialized_der())?.as_ref(),
                )?;
                // If the cert can be loaded, build the thing.
                builder.check_private_key().map(|()| builder.build())
            })()
            .expect("can configure acceptor");

            Self {
                ssl_acceptor,
                tcp: server,
            }
        }

        pub(super) async fn accept(&self) -> (impl AsyncRead + AsyncWrite + Unpin, SocketAddr) {
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
        let tcp_server = TlsServer::new(tcp_server, &PROXY_CERTIFICATE);

        let accepts = futures_util::stream::unfold(tcp_server, move |tcp_server| async move {
            let (ssl_stream, _remote_addr) = tcp_server.accept().await;

            let (sni_names, ssl_stream) = parse_sni_from_stream(ssl_stream).await;
            assert_eq!(sni_names, &[upstream_sni]);
            Some((ssl_stream, tcp_server))
        });
        let proxy = ProxyServer {
            incoming_connections_stream: accepts,
            upstream_addr,
        }
        .proxy();

        (listen_addr, proxy)
    }

    /// Starts a TCP server that proxies TLS connections to an upstream server.
    ///
    /// Proxies TCP connections to `upstream_addr`.
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
