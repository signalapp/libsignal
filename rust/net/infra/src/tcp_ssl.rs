//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use boring_signal::ssl::{ConnectConfiguration, SslConnector, SslMethod, SslSignatureAlgorithm};
use tokio::net::TcpStream;
use tokio_boring_signal::SslStream;

use crate::certs::RootCertificates;
use crate::dns::DnsResolver;
use crate::errors::TransportConnectError;
use crate::host::Host;
use crate::route::{ConnectionProxyConfig, Connector, TcpRoute, TlsRouteFragment};
#[cfg(feature = "dev-util")]
#[allow(unused_imports)]
use crate::utils::development_only_enable_nss_standard_debug_interop;
use crate::{Alpn, AsyncDuplexStream, Connection};

pub mod proxy;

pub const LONG_TCP_HANDSHAKE_THRESHOLD: Duration = Duration::from_secs(3);
pub const LONG_TLS_HANDSHAKE_THRESHOLD: Duration = Duration::from_secs(3);

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

/// Stateless [`Connector`] for [`TcpRoute`]s.
#[derive(Debug, Default)]
pub struct StatelessTcp;

/// Stateless [`Connector`] for [`TlsRouteFragment`]s.
#[derive(Debug, Default)]
pub struct StatelessTls;

impl Connector<TcpRoute<IpAddr>, ()> for StatelessTcp {
    type Connection = TcpStream;

    type Error = TransportConnectError;

    fn connect_over(
        &self,
        (): (),
        route: TcpRoute<IpAddr>,
        log_tag: Arc<str>,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> {
        let TcpRoute { address, port } = route;

        async move {
            let start = tokio::time::Instant::now();
            tokio::time::timeout(
                crate::timeouts::TCP_CONNECTION_TIMEOUT,
                TcpStream::connect((address, port.get())),
            )
            .await
            .map_err(|_| {
                let elapsed = tokio::time::Instant::now() - start;
                log::warn!("{log_tag}: TCP connection timed out after {elapsed:?}");
                TransportConnectError::TcpConnectionFailed
            })?
            .map_err(|_| TransportConnectError::TcpConnectionFailed)
        }
    }
}

impl<Inner> Connector<TlsRouteFragment, Inner> for StatelessTls
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
            min_protocol_version,
        } = fragment;
        let host = sni;

        let ssl_config = ssl_config(&root_certs, host.as_deref(), alpn, min_protocol_version);

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
    min_required_tls_version: Option<boring_signal::ssl::SslVersion>,
) -> Result<ConnectConfiguration, TransportConnectError> {
    let mut ssl = SslConnector::builder(SslMethod::tls_client())?;
    certs.apply_to_connector(&mut ssl, host)?;
    if let Some(alpn) = alpn {
        ssl.set_alpn_protos(alpn.as_ref())?;
    }
    ssl.set_min_proto_version(min_required_tls_version)?;

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
    /// Starts an HTTPS server listening on `::1` that responds with 200 and
    /// [`FAKE_RESPONSE`].
    ///
    /// Returns the address of the server and a [`Future`] that runs it.
    pub(crate) fn localhost_https_server() -> (SocketAddr, impl Future<Output = ()>) {
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
