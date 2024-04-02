//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use boring::ssl::{ConnectConfiguration, SslConnector, SslMethod};
use futures_util::TryFutureExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_boring::SslStream;
use tokio_util::either::Either;

use crate::infra::certs::RootCertificates;
use crate::infra::dns::DnsResolver;
use crate::infra::errors::TransportConnectError;
use crate::infra::{Alpn, ConnectionInfo, ConnectionParams, StreamAndInfo, TransportConnector};
use crate::utils::first_ok;

const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(200);

#[derive(Clone)]
pub enum TcpSslConnector {
    Direct(DirectConnector),
    Proxied(ProxyConnector),
}

pub struct TcpSslConnectorStream(
    Either<
        <DirectConnector as TransportConnector>::Stream,
        <ProxyConnector as TransportConnector>::Stream,
    >,
);

#[derive(Clone)]
pub struct DirectConnector {
    dns_resolver: DnsResolver,
}

#[async_trait]
impl TransportConnector for DirectConnector {
    type Stream = SslStream<TcpStream>;

    async fn connect(
        &self,
        connection_params: &ConnectionParams,
        alpn: Alpn,
    ) -> Result<StreamAndInfo<Self::Stream>, TransportConnectError> {
        let StreamAndInfo(tcp_stream, remote_address) = connect_tcp(
            &self.dns_resolver,
            connection_params.route_type,
            &connection_params.sni,
            connection_params.port,
        )
        .await?;

        let ssl_stream = connect_tls(tcp_stream, connection_params, alpn).await?;

        Ok(StreamAndInfo(ssl_stream, remote_address))
    }
}

impl DirectConnector {
    pub fn new(dns_resolver: DnsResolver) -> Self {
        Self { dns_resolver }
    }

    pub fn with_proxy(&self, proxy_addr: (&str, NonZeroU16)) -> ProxyConnector {
        let Self { dns_resolver } = self;
        ProxyConnector::new(dns_resolver.clone(), proxy_addr)
    }
}

#[derive(Clone)]
pub struct ProxyConnector {
    pub dns_resolver: DnsResolver,
    proxy_host: Arc<str>,
    proxy_port: NonZeroU16,
    proxy_certs: RootCertificates,
}

#[async_trait]
impl TransportConnector for ProxyConnector {
    type Stream = SslStream<SslStream<TcpStream>>;

    async fn connect(
        &self,
        connection_params: &ConnectionParams,
        alpn: Alpn,
    ) -> Result<StreamAndInfo<Self::Stream>, TransportConnectError> {
        let StreamAndInfo(tcp_stream, remote_address) = connect_tcp(
            &self.dns_resolver,
            connection_params.route_type,
            &self.proxy_host,
            self.proxy_port,
        )
        .await?;

        let ssl_config = ssl_config(self.proxy_certs, None)?;

        let outer_ssl = tokio_boring::connect(ssl_config, &self.proxy_host, tcp_stream).await?;

        let tls_stream = connect_tls(outer_ssl, connection_params, alpn).await?;

        Ok(StreamAndInfo(tls_stream, remote_address))
    }
}

impl ProxyConnector {
    pub fn new(dns_resolver: DnsResolver, (proxy_host, proxy_port): (&str, NonZeroU16)) -> Self {
        Self {
            dns_resolver,
            proxy_host: proxy_host.into(),
            proxy_port,
            // We don't bundle roots of trust for all the SSL proxies, just the
            // Signal servers. It's fine to use the system SSL trust roots;
            // even if the outer connection is not secure, the inner connection
            // is also TLS-encrypted.
            proxy_certs: RootCertificates::Native,
        }
    }

    pub fn set_proxy(&mut self, (host, port): (&str, NonZeroU16)) {
        self.proxy_host = host.into();
        self.proxy_port = port;
    }
}

fn ssl_config(
    certs: RootCertificates,
    alpn: Option<Alpn>,
) -> Result<ConnectConfiguration, TransportConnectError> {
    let mut ssl = SslConnector::builder(SslMethod::tls_client())?;
    ssl.set_verify_cert_store(certs.try_into()?)?;
    if let Some(alpn) = alpn {
        ssl.set_alpn_protos(alpn.as_ref())?;
    }
    Ok(ssl.build().configure()?)
}

async fn connect_tls<S: AsyncRead + AsyncWrite + Unpin>(
    transport: S,
    connection_params: &ConnectionParams,
    alpn: Alpn,
) -> Result<SslStream<S>, TransportConnectError> {
    let ssl_config = ssl_config(connection_params.certs, Some(alpn))?;

    Ok(tokio_boring::connect(ssl_config, &connection_params.sni, transport).await?)
}

async fn connect_tcp(
    dns_resolver: &DnsResolver,
    route_type: &'static str,
    host: &str,
    port: NonZeroU16,
) -> Result<StreamAndInfo<TcpStream>, TransportConnectError> {
    let dns_lookup = dns_resolver
        .lookup_ip(host)
        .await
        .map_err(|_| TransportConnectError::DnsError)?;

    if dns_lookup.is_empty() {
        return Err(TransportConnectError::DnsError);
    }

    let dns_source = dns_lookup.source();

    // The idea is to go through the list of candidate IP addresses
    // and to attempt a connection to each of them, giving each one a `CONNECTION_ATTEMPT_DELAY` headstart
    // before moving on to the next candidate.
    // The process stops once we have a successful connection.

    // First, for each resolved IP address, constructing a future
    // that incorporates the delay based on its position in the list.
    // This way we can start all futures at once and simply wait for the first one to complete successfully.
    let staggered_futures = dns_lookup.into_iter().enumerate().map(|(idx, ip)| {
        let delay = CONNECTION_ATTEMPT_DELAY * idx.try_into().unwrap();
        async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            TcpStream::connect((ip, port.into()))
                .inspect_err(|e| {
                    log::debug!("failed to connect to IP [{}] with an error: {:?}", ip, e)
                })
                .await
                .map(|r| {
                    StreamAndInfo(
                        r,
                        ConnectionInfo {
                            route_type,
                            dns_source,
                            address: ip_addr_to_host(ip),
                        },
                    )
                })
        }
    });

    first_ok(staggered_futures)
        .await
        .ok_or(TransportConnectError::TcpConnectionFailed)
}

fn ip_addr_to_host(ip: IpAddr) -> url::Host {
    match ip {
        IpAddr::V4(v4) => url::Host::Ipv4(v4),
        IpAddr::V6(v6) => url::Host::Ipv6(v6),
    }
}

impl AsyncRead for TcpSslConnectorStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpSslConnectorStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[async_trait]
impl TransportConnector for TcpSslConnector {
    type Stream = TcpSslConnectorStream;

    async fn connect(
        &self,
        connection_params: &ConnectionParams,
        alpn: Alpn,
    ) -> Result<StreamAndInfo<Self::Stream>, TransportConnectError> {
        match self {
            Self::Direct(direct) => direct
                .connect(connection_params, alpn)
                .await
                .map(|s| s.map_stream(Either::Left)),
            Self::Proxied(proxied) => proxied
                .connect(connection_params, alpn)
                .await
                .map(|s| s.map_stream(Either::Right)),
        }
        .map(|s| s.map_stream(TcpSslConnectorStream))
    }
}

impl From<DirectConnector> for TcpSslConnector {
    fn from(value: DirectConnector) -> Self {
        Self::Direct(value)
    }
}

impl From<ProxyConnector> for TcpSslConnector {
    fn from(value: ProxyConnector) -> Self {
        Self::Proxied(value)
    }
}

#[cfg(test)]
mod testutil {
    use std::future::Future;
    use std::net::{Ipv6Addr, SocketAddr};

    use assert_matches::assert_matches;
    use boring::pkey::PKey;
    use boring::ssl::{SslAcceptor, SslMethod};
    use boring::x509::X509;
    use lazy_static::lazy_static;
    use rcgen::CertifiedKey;
    use tls_parser::{ClientHello, TlsExtension, TlsMessage, TlsMessageHandshake, TlsPlaintext};
    use tokio::io::{
        AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufStream,
    };
    use warp::Filter;

    pub(super) const SERVER_HOSTNAME: &str = "test-server.signal.org.local";

    lazy_static! {
        pub(super) static ref SERVER_CERTIFICATE: CertifiedKey =
            rcgen::generate_simple_self_signed([SERVER_HOSTNAME.to_string()])
                .expect("can generate");
    }

    const FAKE_RESPONSE: &str = "Hello there";
    /// Starts an HTTP server listening on `::1` that responds with 200 and
    /// [`FAKE_RESPONSE`].
    ///
    /// Returns the address of the server and a [`Future`] that runs it.
    pub(super) fn localhost_http_server() -> (SocketAddr, impl Future<Output = ()>) {
        let filter = warp::any().map(|| FAKE_RESPONSE);
        let server = warp::serve(filter)
            .tls()
            .cert(SERVER_CERTIFICATE.cert.pem())
            .key(SERVER_CERTIFICATE.key_pair.serialize_pem());

        server.bind_ephemeral((Ipv6Addr::LOCALHOST, 0))
    }

    /// Makes an HTTP request on the provided stream and asserts on the response.
    ///
    /// Asserts that the server returns 200 and [`FAKE_RESPONSE`].
    pub(super) async fn make_http_request_response_over(
        mut stream: impl AsyncRead + AsyncWrite + Unpin,
    ) {
        stream
            .write_all(b"GET /index HTTP/1.1\r\nConnection: close\r\n\r\n")
            .await
            .expect("can send request");

        let response = {
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .await
                .expect("receives response");
            response
        };
        let lines = response.lines().collect::<Vec<_>>();

        assert_eq!(lines.first(), Some("HTTP/1.1 200 OK").as_ref(), "{lines:?}");
        assert_eq!(lines.last(), Some(FAKE_RESPONSE).as_ref(), "{lines:?}");
    }

    pub(super) const PROXY_HOSTNAME: &str = "test-proxy.signal.org.local";

    lazy_static! {
        pub(super) static ref PROXY_CERTIFICATE: CertifiedKey =
            rcgen::generate_simple_self_signed([PROXY_HOSTNAME.to_string()]).expect("can generate");
    }

    /// Starts a TLS server that proxies TLS connections to an upstream server.
    ///
    /// Proxies TLS connections with `upstream_sni` to `upstream_addr`.
    pub(super) fn localhost_tls_proxy(
        upstream_sni: &'static str,
        upstream_addr: SocketAddr,
    ) -> (SocketAddr, impl Future<Output = ()>) {
        // TODO(https://github.com/rust-lang/rust/issues/31436): use a `try`
        // block instead of immediately-invoked closure.
        let ssl_acceptor = (|| {
            let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
            builder.set_certificate(X509::from_der(PROXY_CERTIFICATE.cert.der())?.as_ref())?;
            builder.set_private_key(
                PKey::private_key_from_der(PROXY_CERTIFICATE.key_pair.serialized_der())?.as_ref(),
            )?;
            // If the cert can be loaded, build the thing.
            builder.check_private_key().map(|()| builder.build())
        })()
        .expect("can configure acceptor");

        let listener = std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).expect("can bind");
        let listen_addr = listener.local_addr().expect("is bound to local addr");
        let tcp_listener = tokio::net::TcpListener::from_std(listener).expect("can use std socket");
        let proxy = async move {
            loop {
                let (tcp_stream, _remote_addr) =
                    tcp_listener.accept().await.expect("incoming connection");
                let ssl_stream = tokio_boring::accept(&ssl_acceptor, tcp_stream)
                    .await
                    .expect("handshake successful");

                let (sni_names, mut ssl_stream) = parse_sni_from_stream(ssl_stream).await;
                assert_eq!(sni_names, &[upstream_sni]);

                // Now connect to the upstream and then proxy for the life of the connection.
                let mut upstream_stream = tokio::net::TcpStream::connect(upstream_addr)
                    .await
                    .expect("can connect to upstream");
                tokio::io::copy_bidirectional(&mut ssl_stream, &mut upstream_stream)
                    .await
                    .expect("can proxy");
            }
        };

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
    use std::collections::HashMap;
    use std::net::Ipv6Addr;

    use assert_matches::assert_matches;

    use crate::infra::dns::LookupResult;
    use crate::infra::HttpRequestDecoratorSeq;

    use super::testutil::*;
    use super::*;

    #[tokio::test]
    async fn connect_to_server() {
        let (addr, server) = localhost_http_server();
        let _server_handle = tokio::spawn(server);

        let connector = DirectConnector::new(DnsResolver::new_with_static_fallback(HashMap::from(
            [(SERVER_HOSTNAME, LookupResult::localhost())],
        )));
        let connection_params = ConnectionParams {
            route_type: "test",
            sni: SERVER_HOSTNAME.into(),
            host: addr.ip().to_string().into(),
            port: addr.port().try_into().expect("bound port"),
            http_request_decorator: HttpRequestDecoratorSeq::default(),
            certs: RootCertificates::FromDer(SERVER_CERTIFICATE.cert.der()),
        };

        let StreamAndInfo(stream, info) = connector
            .connect(&connection_params, Alpn::Http1_1)
            .await
            .expect("can connect");

        assert_eq!(
            info,
            ConnectionInfo {
                address: url::Host::Ipv6(Ipv6Addr::LOCALHOST),
                dns_source: crate::infra::DnsSource::Static,
                route_type: "test"
            }
        );

        make_http_request_response_over(stream).await
    }

    #[tokio::test]
    async fn connect_through_proxy() {
        let (addr, server) = localhost_http_server();
        let _server_handle = tokio::spawn(server);

        let (proxy_addr, proxy) = localhost_tls_proxy(SERVER_HOSTNAME, addr);
        let _proxy_handle = tokio::spawn(proxy);

        // Ensure that the proxy is doing the right thing
        let mut connector = ProxyConnector::new(
            DnsResolver::new_with_static_fallback(HashMap::from([(
                PROXY_HOSTNAME,
                LookupResult::localhost(),
            )])),
            (PROXY_HOSTNAME, proxy_addr.port().try_into().unwrap()),
        );
        // Override the SSL certificate for the proxy; since it's self-signed,
        // it won't work with the default config.
        let default_root_cert = std::mem::replace(
            &mut connector.proxy_certs,
            RootCertificates::FromDer(PROXY_CERTIFICATE.cert.der()),
        );
        assert_matches!(default_root_cert, RootCertificates::Native);

        let connection_params = ConnectionParams {
            route_type: "test",
            sni: SERVER_HOSTNAME.into(),
            host: "localhost".to_string().into(),
            port: addr.port().try_into().expect("bound port"),
            http_request_decorator: HttpRequestDecoratorSeq::default(),
            certs: RootCertificates::FromDer(SERVER_CERTIFICATE.cert.der()),
        };

        let StreamAndInfo(stream, info) = connector
            .connect(&connection_params, Alpn::Http1_1)
            .await
            .expect("can connect");

        assert_eq!(
            info,
            ConnectionInfo {
                address: url::Host::Ipv6(Ipv6Addr::LOCALHOST),
                dns_source: crate::infra::DnsSource::Static,
                route_type: "test"
            }
        );

        make_http_request_response_over(stream).await;
    }
}
