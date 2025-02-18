//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;

use async_trait::async_trait;
use auto_enums::enum_derive;
use boring_signal::ssl::{ConnectConfiguration, SslConnector, SslMethod, SslSignatureAlgorithm};
use futures_util::TryFutureExt;
use tokio::net::TcpStream;
use tokio_boring_signal::SslStream;

use crate::certs::RootCertificates;
use crate::dns::DnsResolver;
use crate::errors::TransportConnectError;
use crate::host::Host;
use crate::route::{
    ConnectionProxyConfig, Connector, ConnectorExt as _, TcpProxy, TcpRoute, TlsProxy,
    TlsRouteFragment,
};
use crate::tcp_ssl::proxy::tls::TlsProxyConnector;
use crate::timeouts::TCP_CONNECTION_ATTEMPT_DELAY;
#[cfg(feature = "dev-util")]
#[allow(unused_imports)]
use crate::utils::development_only_enable_nss_standard_debug_interop;
use crate::utils::first_ok;
use crate::{
    Alpn, AsyncDuplexStream, Connection, RouteType, ServiceConnectionInfo, StreamAndInfo,
    TransportConnectionParams, TransportConnector,
};

pub mod proxy;

#[derive(Clone, Debug)]
pub struct TcpSslConnector {
    dns_resolver: DnsResolver,
    proxy: Result<Option<ConnectionProxyConfig>, InvalidProxyConfig>,
}

impl TcpSslConnector {
    pub fn new_direct(dns_resolver: DnsResolver) -> Self {
        Self {
            dns_resolver,
            proxy: Ok(None),
        }
    }

    pub fn set_ipv6_enabled(&mut self, ipv6_enabled: bool) {
        self.dns_resolver.set_ipv6_enabled(ipv6_enabled);
    }

    pub fn set_proxy(&mut self, proxy: ConnectionProxyConfig) {
        self.proxy = Ok(Some(proxy));
    }

    pub fn set_invalid(&mut self) {
        self.proxy = Err(InvalidProxyConfig)
    }

    pub fn clear_proxy(&mut self) {
        self.proxy = Ok(None);
    }

    pub fn proxy(&self) -> Result<Option<&ConnectionProxyConfig>, InvalidProxyConfig> {
        self.proxy
            .as_ref()
            .map(Option::as_ref)
            .map_err(InvalidProxyConfig::clone)
    }
}

#[derive(Clone, Debug)]
pub struct InvalidProxyConfig;

impl TryFrom<&TcpSslConnector> for Option<ConnectionProxyConfig> {
    type Error = InvalidProxyConfig;

    fn try_from(value: &TcpSslConnector) -> Result<Self, Self::Error> {
        let TcpSslConnector {
            dns_resolver: _,
            proxy,
        } = value;
        proxy.clone()
    }
}

#[enum_derive(tokio1::AsyncRead, tokio1::AsyncWrite)]
pub enum TcpSslConnectorStream {
    Direct(<DirectConnector as TransportConnector>::Stream),
    Proxy(<TlsProxyConnector as TransportConnector>::Stream),
}

#[derive(Clone, Debug)]
pub struct DirectConnector {
    pub dns_resolver: DnsResolver,
}

#[derive(Debug, Default)]
pub struct StatelessDirect;

#[async_trait]
impl TransportConnector for DirectConnector {
    type Stream = SslStream<TcpStream>;

    async fn connect(
        &self,
        connection_params: &TransportConnectionParams,
        alpn: Alpn,
    ) -> Result<StreamAndInfo<Self::Stream>, TransportConnectError> {
        let log_tag: Arc<str> = "DirectConnector".into();
        let StreamAndInfo(tcp_stream, remote_address) = connect_tcp(
            &self.dns_resolver,
            RouteType::Direct,
            connection_params.tcp_host.as_deref(),
            connection_params.port,
            log_tag.clone(),
        )
        .await?;

        let ssl_stream = connect_tls(tcp_stream, connection_params, alpn, log_tag).await?;

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

impl Connector<TcpRoute<IpAddr>, ()> for StatelessDirect {
    type Connection = TcpStream;

    type Error = TransportConnectError;

    fn connect_over(
        &self,
        (): (),
        route: TcpRoute<IpAddr>,
        _log_tag: Arc<str>,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> {
        let TcpRoute { address, port } = route;

        TcpStream::connect((address, port.get()))
            .map_err(|_e| TransportConnectError::TcpConnectionFailed)
    }
}

impl<Inner> Connector<TlsRouteFragment, Inner> for StatelessDirect
where
    Inner: AsyncDuplexStream,
{
    type Connection = tokio_boring_signal::SslStream<Inner>;

    type Error = TransportConnectError;

    fn connect_over(
        &self,
        inner: Inner,
        fragment: TlsRouteFragment,
        _log_tag: Arc<str>,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let TlsRouteFragment {
            root_certs,
            sni,
            alpn,
        } = fragment;
        let host = sni;

        let ssl_config =
            ssl_config(&root_certs, host.as_deref(), alpn).map_err(TransportConnectError::from);

        async move {
            let domain = match &host {
                Host::Ip(ip_addr) => either::Either::Left(ip_addr.to_string()),
                Host::Domain(domain) => either::Either::Right(&**domain),
            };
            let ssl_config = ssl_config?;

            tokio_boring_signal::connect(ssl_config, &domain, inner)
                .await
                .map_err(TransportConnectError::from)
        }
    }
}

impl<S: Connection> Connection for SslStream<S> {
    fn transport_info(&self) -> crate::TransportInfo {
        self.get_ref().transport_info()
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

    // This is just the default Boring TLS supported signature scheme list
    //   with ed25519 added at the top of the preference order.
    // We can't be any more specific because of the fallback proxies.
    ssl.set_verify_algorithm_prefs(&[
        SslSignatureAlgorithm::ED25519,
        SslSignatureAlgorithm::RSA_PSS_RSAE_SHA256,
        SslSignatureAlgorithm::RSA_PKCS1_SHA256,
        SslSignatureAlgorithm::ECDSA_SECP256R1_SHA256,
        SslSignatureAlgorithm::RSA_PKCS1_SHA1,
        SslSignatureAlgorithm::ECDSA_SHA1,
    ])?;

    // Uncomment and build with the feature "dev-util" to enable NSS-standard
    //   debugging support for e.g. Wireshark.
    // This is already built into BoringSSL and RustTLS, so there is no added risk here,
    //   but we need to provide a callback manually for it to work for us.
    // See: https://udn.realityripple.com/docs/Mozilla/Projects/NSS/Key_Log_Format
    // #[cfg(feature = "dev-util")]
    // development_only_enable_nss_standard_debug_interop(&mut ssl)?;

    Ok(ssl.build().configure()?)
}

async fn connect_tls<S: AsyncDuplexStream>(
    transport: S,
    connection_params: &TransportConnectionParams,
    alpn: Alpn,
    log_tag: Arc<str>,
) -> Result<SslStream<S>, TransportConnectError> {
    let route = TlsRouteFragment {
        root_certs: connection_params.certs.clone(),
        sni: Host::Domain(Arc::clone(&connection_params.sni)),
        alpn: Some(alpn),
    };

    StatelessDirect
        .connect_over(transport, route, log_tag)
        .await
}

async fn connect_tcp(
    dns_resolver: &DnsResolver,
    route_type: RouteType,
    host: Host<&str>,
    port: NonZeroU16,
    log_tag: Arc<str>,
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
    let connector = StatelessDirect;
    let staggered_futures = dns_lookup.into_iter().enumerate().map(|(idx, ip)| {
        let delay = TCP_CONNECTION_ATTEMPT_DELAY * idx.try_into().unwrap();
        let connector = &connector;
        let log_tag = log_tag.clone();
        async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let route = TcpRoute { address: ip, port };
            connector
                .connect(route, log_tag)
                .inspect_err(|e| {
                    log::debug!("failed to connect to IP [{ip}] with an error: {e:?}");
                })
                .await
                .map(|r| {
                    log::debug!("successfully connected to IP [{ip}]");
                    StreamAndInfo(
                        r,
                        ServiceConnectionInfo {
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

#[async_trait]
impl TransportConnector for TcpSslConnector {
    type Stream = TcpSslConnectorStream;

    async fn connect(
        &self,
        connection_params: &TransportConnectionParams,
        alpn: Alpn,
    ) -> Result<StreamAndInfo<Self::Stream>, TransportConnectError> {
        let Self {
            dns_resolver,
            proxy,
        } = self;
        let proxy = proxy
            .as_ref()
            .map_err(|InvalidProxyConfig| TransportConnectError::InvalidConfiguration)?;

        let stream_and_info = match proxy {
            None => {
                let stream_and_info = DirectConnector {
                    dns_resolver: dns_resolver.clone(),
                }
                .connect(connection_params, alpn)
                .await?;

                stream_and_info.map_stream(TcpSslConnectorStream::Direct)
            }
            Some(ConnectionProxyConfig::Tcp(TcpProxy {
                proxy_host,
                proxy_port,
            })) => {
                let connector = TlsProxyConnector::new_tcp(
                    dns_resolver.clone(),
                    (proxy_host.clone(), *proxy_port),
                );
                let stream_and_info = connector.connect(connection_params, alpn).await?;
                stream_and_info.map_stream(TcpSslConnectorStream::Proxy)
            }
            Some(ConnectionProxyConfig::Tls(TlsProxy {
                proxy_host,
                proxy_port,
                proxy_certs,
            })) => {
                let mut connector =
                    TlsProxyConnector::new(dns_resolver.clone(), (proxy_host.clone(), *proxy_port));
                connector.proxy_certs = proxy_certs.clone();
                let stream_and_info = connector.connect(connection_params, alpn).await?;
                stream_and_info.map_stream(TcpSslConnectorStream::Proxy)
            }
            Some(ConnectionProxyConfig::Socks(_) | ConnectionProxyConfig::Http(_)) => {
                log::warn!("SOCKS and HTTP proxies are not supported by TransportConnector");
                return Err(TransportConnectError::InvalidConfiguration);
            }
        };

        Ok(stream_and_info)
    }
}

#[cfg(test)]
pub(crate) mod testutil {
    use std::future::Future;
    use std::net::{Ipv6Addr, SocketAddr};
    use std::sync::LazyLock;

    use rcgen::CertifiedKey;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use warp::Filter;

    pub(crate) const SERVER_HOSTNAME: &str = "test-server.signal.org.local";

    pub(crate) static SERVER_CERTIFICATE: LazyLock<CertifiedKey> = LazyLock::new(|| {
        rcgen::generate_simple_self_signed([SERVER_HOSTNAME.to_string()]).expect("can generate")
    });

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
            ServiceConnectionInfo {
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

        let connector = TcpSslConnector {
            dns_resolver: DnsResolver::new_from_static_map(HashMap::from([(
                SERVER_HOSTNAME,
                LookupResult::localhost(),
            )])),
            proxy: Err(InvalidProxyConfig),
        };
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
