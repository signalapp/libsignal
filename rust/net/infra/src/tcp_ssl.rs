//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use boring_signal::ssl::{ConnectConfiguration, SslConnector, SslMethod, SslSignatureAlgorithm};
use tokio_boring_signal::SslStream;

use crate::certs::RootCertificates;
use crate::dns::DnsResolver;
use crate::errors::TransportConnectError;
use crate::host::Host;
use crate::route::{Connector, DirectOrProxyMode, TcpRoute, TlsRouteFragment};
#[cfg(feature = "dev-util")]
#[allow(unused_imports)]
use crate::utils::development_only_enable_nss_standard_debug_interop;
use crate::{Alpn, AsyncDuplexStream, Connection};

pub mod proxy;

pub const LONG_TCP_HANDSHAKE_THRESHOLD: Duration = Duration::from_secs(3);
pub const LONG_TLS_HANDSHAKE_THRESHOLD: Duration = Duration::from_secs(3);

#[cfg(target_os = "macos")]
pub type TcpStream = crate::stream::WorkaroundWriteBugDuplexStream<tokio::net::TcpStream>;
#[cfg(not(target_os = "macos"))]
pub type TcpStream = tokio::net::TcpStream;

#[derive(Clone, Debug)]
pub struct TcpSslConnector {
    dns_resolver: DnsResolver,
    proxy_mode: Result<DirectOrProxyMode, InvalidProxyConfig>,
}

impl TcpSslConnector {
    pub fn new_direct(dns_resolver: DnsResolver) -> Self {
        Self {
            dns_resolver,
            proxy_mode: Ok(DirectOrProxyMode::DirectOnly),
        }
    }

    pub fn set_ipv6_enabled(&mut self, ipv6_enabled: bool) {
        self.dns_resolver.set_ipv6_enabled(ipv6_enabled);
    }

    pub fn set_proxy_mode(&mut self, proxy_mode: DirectOrProxyMode) {
        self.proxy_mode = Ok(proxy_mode);
    }

    pub fn set_invalid(&mut self) {
        self.proxy_mode = Err(InvalidProxyConfig)
    }

    pub fn proxy(&self) -> Result<&DirectOrProxyMode, InvalidProxyConfig> {
        self.proxy_mode.as_ref().map_err(InvalidProxyConfig::clone)
    }
}

#[derive(Clone, Debug)]
pub struct InvalidProxyConfig;

impl TryFrom<&TcpSslConnector> for DirectOrProxyMode {
    type Error = InvalidProxyConfig;

    fn try_from(value: &TcpSslConnector) -> Result<Self, Self::Error> {
        let TcpSslConnector {
            dns_resolver: _,
            proxy_mode,
        } = value;
        proxy_mode.clone()
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
        log_tag: &str,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> {
        let TcpRoute { address, port } = route;

        async move {
            let start = tokio::time::Instant::now();
            let result = tokio::time::timeout(
                crate::timeouts::TCP_CONNECTION_TIMEOUT,
                tokio::net::TcpStream::connect((address, port.get())),
            )
            .await
            .map_err(|_| {
                let elapsed = tokio::time::Instant::now() - start;
                log::warn!("{log_tag}: TCP connection timed out after {elapsed:?}");
                TransportConnectError::TcpConnectionFailed
            })?
            .map_err(|e| {
                let error_kind = e.kind();
                // The raw error might provide marginally more information than the kind,
                //   and it takes a long time to rollout logging, so let's just add it now.
                let os_error = e.raw_os_error();
                log::info!(
                    "{log_tag}: TCP connection failed: kind={error_kind:?}, errno={os_error:?}"
                );
                TransportConnectError::TcpConnectionFailed
            })?;
            #[cfg(target_os = "macos")]
            let result = crate::stream::WorkaroundWriteBugDuplexStream::new(result);
            Ok(result)
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
        _log_tag: &str,
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

    use const_str::concat_bytes;
    use futures_util::TryFuture;
    use rcgen::CertifiedKey;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use warp::Filter;

    pub(crate) const SERVER_HOSTNAME: &str = "test-server.signal.org.local";

    pub(crate) static SERVER_CERTIFICATE: LazyLock<CertifiedKey> = LazyLock::new(|| {
        rcgen::generate_simple_self_signed([SERVER_HOSTNAME.to_string()]).expect("can generate")
    });

    /// Starts an HTTPS server on `::1` using [`SERVER_CERTIFICATE`] and the provided `warp` filter.
    ///
    /// The resulting future **must be run on a tokio context** if using HTTP/2, since it needs to
    /// spawn additional tasks to maintain connections. Note that as implemented it can **only serve
    /// one connection at a time**; this is not an insurmountable restriction, but merely keeping
    /// the code simple.
    ///
    /// The complicated generics are an attempt to mimic [`warp::service`]'s requirements;
    /// unfortunately, `warp` uses a lot of non-public and unnameable types.
    pub(crate) fn localhost_https_server<F>(service: F) -> (SocketAddr, impl Future<Output = ()>)
    where
        F: warp::Filter<Error = std::convert::Infallible> + Send + Clone + 'static,
        <F::Future as TryFuture>::Ok: warp::Reply,
    {
        // We're essentially rebuilding warp::serve, but with a TLS layer in the middle. warp used
        // to provide this in a convenient package, but no longer. So we manually send up a TCP
        // listener, then using Boring to run the server-side TLS, then use Hyper to handle the HTTP
        // framing, before finally handing things off to our Warp filter.
        let listener =
            std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).expect("can bind to localhost");
        listener
            .set_nonblocking(true)
            .expect("can make nonblocking");
        let addr = listener.local_addr().expect("successful bind");

        let listener_task = async move {
            let listener =
                tokio::net::TcpListener::from_std(listener).expect("can convert to tokio");

            let private_key = boring_signal::pkey::PKey::private_key_from_der(
                SERVER_CERTIFICATE.key_pair.serialized_der(),
            )
            .expect("valid key");
            let cert = boring_signal::x509::X509::from_der(SERVER_CERTIFICATE.cert.der())
                .expect("valid certificate");
            // ALPN "wire format", a sequence of length-prefixed protocol names.
            // See https://docs.rs/boring/4.19.0/boring/ssl/struct.SslContextBuilder.html#method.set_alpn_protos.
            const ALPN_HTTP_1_1: &[u8] = b"http/1.1";
            const ALPN_H2: &[u8] = b"h2";
            #[allow(clippy::cast_possible_truncation)]
            const SERVER_SUPPORTED_ALPN: &[u8] = concat_bytes!(
                ALPN_H2.len() as u8,
                ALPN_H2,
                ALPN_HTTP_1_1.len() as u8,
                ALPN_HTTP_1_1
            );

            // This loop means the server can process multiple connections, but as written it will
            // process them serially. If that's ever a problem this can be rewritten to collect
            // active connection tasks and poll them alongside listening for new ones.
            loop {
                let (stream, _addr) = listener
                    .accept()
                    .await
                    .expect("can accept an incoming connection");

                let mut tls_acceptor = boring_signal::ssl::SslAcceptor::mozilla_modern(
                    boring_signal::ssl::SslMethod::tls_server(),
                )
                .expect("can build");
                tls_acceptor
                    .set_private_key(&private_key)
                    .expect("valid key");
                tls_acceptor
                    .set_certificate(&cert)
                    .expect("valid certificate");
                tls_acceptor.set_alpn_select_callback(move |_, client| {
                    boring_signal::ssl::select_next_proto(SERVER_SUPPORTED_ALPN, client)
                        .ok_or(boring_signal::ssl::AlpnError::ALERT_FATAL)
                });
                let tls_acceptor = tls_acceptor.build();

                let stream = tokio_boring_signal::accept(&tls_acceptor, stream)
                    .await
                    .expect("TLS handshake succeeds");
                let stream = hyper_util::rt::TokioIo::new(stream);
                let service =
                    hyper_util::service::TowerToHyperService::new(warp::service(service.clone()));

                match stream.inner().ssl().selected_alpn_protocol() {
                    None | Some(ALPN_HTTP_1_1) => {
                        hyper::server::conn::http1::Builder::new()
                            .serve_connection(stream, service)
                            .await
                            .expect("HTTP/1.1 connection completes without error");
                    }
                    Some(ALPN_H2) => {
                        hyper::server::conn::http2::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(stream, service)
                        .await
                        .expect("H2 connection completes without error");
                    }
                    Some(other) => {
                        unreachable!("should have picked a supported ALPN, but picked {other:?}")
                    }
                }
            }
        };
        (addr, listener_task)
    }

    const FAKE_RESPONSE: &str = "Hello there";
    /// Starts an HTTPS server listening on `::1` that responds with 200 and
    /// [`FAKE_RESPONSE`].
    ///
    /// Returns the address of the server and a [`Future`] that runs it.
    pub(crate) fn simple_localhost_https_server() -> (SocketAddr, impl Future<Output = ()>) {
        localhost_https_server(warp::any().map(|| FAKE_RESPONSE))
    }

    /// Makes an HTTP request on the provided stream and asserts on the response.
    ///
    /// Asserts that the server returns 200 and [`FAKE_RESPONSE`].
    pub(crate) async fn make_http_request_response_over(
        mut stream: impl AsyncRead + AsyncWrite + Unpin,
    ) -> Result<(), std::io::Error> {
        stream
            .write_all(b"GET /index HTTP/1.1\r\nConnection: close\r\n\r\n")
            .await?;

        let response = {
            let mut response = String::new();
            stream.read_to_string(&mut response).await?;
            response
        };
        let lines = response.lines().collect::<Vec<_>>();

        assert_eq!(lines.first(), Some("HTTP/1.1 200 OK").as_ref(), "{lines:?}");
        assert_eq!(lines.last(), Some(FAKE_RESPONSE).as_ref(), "{lines:?}");

        Ok(())
    }
}
