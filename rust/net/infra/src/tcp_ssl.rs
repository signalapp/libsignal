//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU16;
use std::sync::Arc;

use async_trait::async_trait;
use boring_signal::ssl::{ConnectConfiguration, SslConnector, SslMethod};
use futures_util::TryFutureExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_boring_signal::SslStream;
use tokio_util::either::Either;

use crate::certs::RootCertificates;
use crate::dns::DnsResolver;
use crate::errors::TransportConnectError;
use crate::host::Host;
use crate::tcp_ssl::proxy::tls::TlsProxyConnector;
use crate::timeouts::TCP_CONNECTION_ATTEMPT_DELAY;
use crate::utils::first_ok;
use crate::{
    Alpn, ConnectionInfo, RouteType, StreamAndInfo, TransportConnectionParams, TransportConnector,
};

pub mod proxy;

#[derive(Clone, Debug)]
pub enum TcpSslConnector {
    Direct(DirectConnector),
    Proxied(TlsProxyConnector),
    /// Used when configuring one of the other kinds of connector isn't possible, perhaps because
    /// invalid configuration options were provided.
    Invalid(DnsResolver),
}

impl TcpSslConnector {
    pub fn set_ipv6_enabled(&mut self, ipv6_enabled: bool) {
        let dns_resolver = match self {
            TcpSslConnector::Direct(c) => &mut c.dns_resolver,
            TcpSslConnector::Proxied(c) => &mut c.dns_resolver,
            TcpSslConnector::Invalid(resolver) => resolver,
        };
        dns_resolver.set_ipv6_enabled(ipv6_enabled);
    }
}

pub struct TcpSslConnectorStream(
    Either<
        <DirectConnector as TransportConnector>::Stream,
        <TlsProxyConnector as TransportConnector>::Stream,
    >,
);

#[derive(Clone, Debug)]
pub struct DirectConnector {
    pub dns_resolver: DnsResolver,
}

#[async_trait]
impl TransportConnector for DirectConnector {
    type Stream = SslStream<TcpStream>;

    async fn connect(
        &self,
        connection_params: &TransportConnectionParams,
        alpn: Alpn,
    ) -> Result<StreamAndInfo<Self::Stream>, TransportConnectError> {
        let StreamAndInfo(tcp_stream, remote_address) = connect_tcp(
            &self.dns_resolver,
            RouteType::Direct,
            connection_params.tcp_host.as_deref(),
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

    pub fn with_proxy(&self, proxy_addr: (Host<Arc<str>>, NonZeroU16)) -> TlsProxyConnector {
        let Self { dns_resolver } = self;
        TlsProxyConnector::new(dns_resolver.clone(), proxy_addr)
    }
}

fn ssl_config(
    certs: &RootCertificates,
    host: Host<&str>,
    alpn: Option<Alpn>,
) -> Result<ConnectConfiguration, TransportConnectError> {
    let mut ssl = SslConnector::builder(SslMethod::tls_client())?;
    certs.apply_to_connector(&mut ssl, host)?;
    if let Some(alpn) = alpn {
        ssl.set_alpn_protos(alpn.as_ref())?;
    }
    Ok(ssl.build().configure()?)
}

async fn connect_tls<S: AsyncRead + AsyncWrite + Unpin>(
    transport: S,
    connection_params: &TransportConnectionParams,
    alpn: Alpn,
) -> Result<SslStream<S>, TransportConnectError> {
    let ssl_config = ssl_config(
        &connection_params.certs,
        Host::Domain(&connection_params.sni),
        Some(alpn),
    )?;

    Ok(tokio_boring_signal::connect(ssl_config, &connection_params.sni, transport).await?)
}

async fn connect_tcp(
    dns_resolver: &DnsResolver,
    route_type: RouteType,
    host: Host<&str>,
    port: NonZeroU16,
) -> Result<StreamAndInfo<TcpStream>, TransportConnectError> {
    let dns_lookup = match host {
        Host::Ip(ip) => {
            let (ipv4, ipv6) = match ip {
                std::net::IpAddr::V4(v4) => (vec![v4], vec![]),
                std::net::IpAddr::V6(v6) => (vec![], vec![v6]),
            };
            crate::dns::lookup_result::LookupResult {
                source: crate::DnsSource::Static,
                ipv4,
                ipv6,
            }
        }
        Host::Domain(domain) => dns_resolver
            .lookup_ip(domain)
            .await
            .map_err(|_| TransportConnectError::DnsError)?,
    };

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
        let delay = TCP_CONNECTION_ATTEMPT_DELAY * idx.try_into().unwrap();
        async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            TcpStream::connect((ip, port.into()))
                .inspect_err(|e| {
                    log::debug!("failed to connect to IP [{ip}] with an error: {e:?}");
                })
                .await
                .map(|r| {
                    log::debug!("successfully connected to IP [{ip}]");
                    StreamAndInfo(
                        r,
                        ConnectionInfo {
                            route_type,
                            dns_source,
                            address: ip.into(),
                        },
                    )
                })
        }
    });

    first_ok(staggered_futures)
        .await
        .ok_or(TransportConnectError::TcpConnectionFailed)
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
        connection_params: &TransportConnectionParams,
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
            Self::Invalid(_) => Err(TransportConnectError::InvalidConfiguration),
        }
        .map(|s| s.map_stream(TcpSslConnectorStream))
    }
}

impl From<DirectConnector> for TcpSslConnector {
    fn from(value: DirectConnector) -> Self {
        Self::Direct(value)
    }
}

impl From<TlsProxyConnector> for TcpSslConnector {
    fn from(value: TlsProxyConnector) -> Self {
        Self::Proxied(value)
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::future::Future;
    use std::net::{Ipv6Addr, SocketAddr};

    use lazy_static::lazy_static;
    use rcgen::CertifiedKey;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use warp::Filter;

    pub(crate) const SERVER_HOSTNAME: &str = "test-server.signal.org.local";

    lazy_static! {
        pub(crate) static ref SERVER_CERTIFICATE: CertifiedKey =
            rcgen::generate_simple_self_signed([SERVER_HOSTNAME.to_string()])
                .expect("can generate");
    }

    const FAKE_RESPONSE: &str = "Hello there";
    /// Starts an HTTP server listening on `::1` that responds with 200 and
    /// [`FAKE_RESPONSE`].
    ///
    /// Returns the address of the server and a [`Future`] that runs it.
    pub(crate) fn localhost_http_server() -> (SocketAddr, impl Future<Output = ()>) {
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
    pub(crate) async fn make_http_request_response_over(
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
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::net::Ipv6Addr;

    use assert_matches::assert_matches;
    use test_case::test_case;

    use super::testutil::*;
    use super::*;
    use crate::dns::lookup_result::LookupResult;
    use crate::host::Host;

    #[test_case(true; "resolved hostname")]
    #[test_case(false; "by IP")]
    #[tokio::test]
    async fn connect_to_server(use_hostname: bool) {
        let (addr, server) = localhost_http_server();
        let _server_handle = tokio::spawn(server);

        let connector = DirectConnector::new(DnsResolver::new_from_static_map(HashMap::from([(
            SERVER_HOSTNAME,
            LookupResult::localhost(),
        )])));
        let connection_params = TransportConnectionParams {
            sni: SERVER_HOSTNAME.into(),
            tcp_host: match use_hostname {
                true => Host::Domain(SERVER_HOSTNAME.into()),
                false => addr.ip().into(),
            },
            port: addr.port().try_into().expect("bound port"),
            certs: RootCertificates::FromDer(Cow::Borrowed(SERVER_CERTIFICATE.cert.der())),
        };

        let StreamAndInfo(stream, info) = connector
            .connect(&connection_params, Alpn::Http1_1)
            .await
            .expect("can connect");

        assert_eq!(
            info,
            ConnectionInfo {
                address: Host::Ip(Ipv6Addr::LOCALHOST.into()),
                dns_source: crate::DnsSource::Static,
                route_type: RouteType::Direct,
            }
        );

        make_http_request_response_over(stream).await
    }

    #[tokio::test]
    async fn connect_through_invalid() {
        let (addr, server) = localhost_http_server();
        let _server_handle = tokio::spawn(server);

        let connector = TcpSslConnector::Invalid(DnsResolver::new_from_static_map(HashMap::from(
            [(SERVER_HOSTNAME, LookupResult::localhost())],
        )));
        let connection_params = TransportConnectionParams {
            sni: SERVER_HOSTNAME.into(),
            tcp_host: Host::Ip(addr.ip()),
            port: addr.port().try_into().expect("bound port"),
            certs: RootCertificates::FromDer(Cow::Borrowed(SERVER_CERTIFICATE.cert.der())),
        };

        match connector.connect(&connection_params, Alpn::Http1_1).await {
            Ok(_) => {
                // We can't use expect_err() or assert_matches! because the success case isn't Debug.
                panic!("should have failed");
            }
            Err(e) => {
                assert_matches!(e, TransportConnectError::InvalidConfiguration);
            }
        }
    }
}
