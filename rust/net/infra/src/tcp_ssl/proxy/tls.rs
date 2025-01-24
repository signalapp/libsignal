//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU16;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio_boring_signal::SslStream;
use tokio_util::either::Either;

use crate::certs::RootCertificates;
use crate::dns::DnsResolver;
use crate::errors::TransportConnectError;
use crate::host::Host;
use crate::tcp_ssl::{connect_tcp, connect_tls, ssl_config};
use crate::{
    Alpn, RouteType, ServiceConnectionInfo, StreamAndInfo, TransportConnectionParams,
    TransportConnector,
};

/// A [`TransportConnector`] that proxies through a TLS server.
///
/// The proxy server should expose a listening port. If `use_tls_for_proxy` is
/// `ShouldUseTls::Yes`, the port should accept TLS client connections;
/// otherwise unencrypted. The proxy will transparently proxy TLS traffic by
/// examining the SNI of incoming connections to determine the destination host.
///
/// An example implementation of such a target service can be found at
/// <https://github.com/signalapp/Signal-TLS-Proxy>.
#[derive(Clone, Debug)]
pub struct TlsProxyConnector {
    pub dns_resolver: DnsResolver,
    proxy_host: Host<Arc<str>>,
    proxy_port: NonZeroU16,
    pub(crate) proxy_certs: RootCertificates,
    use_tls_for_proxy: ShouldUseTls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShouldUseTls {
    No,
    Yes,
}

#[async_trait]
impl TransportConnector for TlsProxyConnector {
    type Stream = SslStream<Either<SslStream<TcpStream>, TcpStream>>;

    async fn connect(
        &self,
        connection_params: &TransportConnectionParams,
        alpn: Alpn,
    ) -> Result<StreamAndInfo<Self::Stream>, TransportConnectError> {
        let log_tag: Arc<str> = "TlsProxyConnector".into();
        let StreamAndInfo(tcp_stream, remote_address) = connect_tcp(
            &self.dns_resolver,
            RouteType::TlsProxy,
            self.proxy_host.as_deref(),
            self.proxy_port,
            log_tag.clone(),
        )
        .await?;

        let inner_stream = match self.use_tls_for_proxy {
            ShouldUseTls::Yes => {
                log::debug!(
                    "connecting to proxy {}:{}",
                    self.proxy_host,
                    self.proxy_port
                );
                // This won't always work, but it's enough to connect to proxies
                // by hostnames.
                let ssl_config = ssl_config(&self.proxy_certs, self.proxy_host.as_deref(), None)?;
                Either::Left(
                    tokio_boring_signal::connect(
                        ssl_config,
                        &self.proxy_host.to_string(),
                        tcp_stream,
                    )
                    .await?,
                )
            }
            ShouldUseTls::No => {
                log::debug!(
                    "connecting to proxy {}:{} using TCP",
                    self.proxy_host,
                    self.proxy_port
                );
                Either::Right(tcp_stream)
            }
        };

        let tls_stream = connect_tls(inner_stream, connection_params, alpn, log_tag).await?;

        Ok(StreamAndInfo(
            tls_stream,
            ServiceConnectionInfo {
                route_type: RouteType::TlsProxy,
                ..remote_address
            },
        ))
    }
}

impl TlsProxyConnector {
    pub fn new(
        dns_resolver: DnsResolver,
        (proxy_host, proxy_port): (Host<Arc<str>>, NonZeroU16),
    ) -> Self {
        let (use_tls_for_proxy, actual_host) = Self::parse_host_for_tls_opt_out(proxy_host);

        Self {
            dns_resolver,
            proxy_host: actual_host,
            proxy_port,
            // We don't bundle roots of trust for all the SSL proxies, just the
            // Signal servers. It's fine to use the system SSL trust roots;
            // even if the outer connection is not secure, the inner connection
            // is also TLS-encrypted.
            proxy_certs: RootCertificates::Native,
            use_tls_for_proxy,
        }
    }

    pub(crate) fn new_tcp(dns_resolver: DnsResolver, proxy: (Host<Arc<str>>, NonZeroU16)) -> Self {
        let mut connector = Self::new(dns_resolver, proxy);
        connector.use_tls_for_proxy = ShouldUseTls::No;
        connector
    }

    pub fn set_proxy(&mut self, (host, port): (Host<Arc<str>>, NonZeroU16)) {
        let (use_tls_for_proxy, actual_host) = Self::parse_host_for_tls_opt_out(host);

        self.proxy_host = actual_host.to_owned();
        self.proxy_port = port;
        self.use_tls_for_proxy = use_tls_for_proxy;
    }

    fn parse_host_for_tls_opt_out(proxy_host: Host<Arc<str>>) -> (ShouldUseTls, Host<Arc<str>>) {
        if let Host::Domain(domain) = &proxy_host {
            if let Some(host) = domain.strip_prefix("UNENCRYPTED_FOR_TESTING@") {
                return (ShouldUseTls::No, Host::Domain(host.into()));
            }
        }

        (ShouldUseTls::Yes, proxy_host)
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::net::Ipv6Addr;

    use assert_matches::assert_matches;

    use super::super::super::testutil::*;
    use super::*;
    use crate::dns::lookup_result::LookupResult;
    use crate::host::Host;
    use crate::tcp_ssl::proxy::testutil::{
        localhost_tcp_proxy, localhost_tls_proxy, PROXY_CERTIFICATE, PROXY_HOSTNAME,
    };

    #[tokio::test]
    async fn connect_through_proxy() {
        let (addr, server) = localhost_http_server();
        let _server_handle = tokio::spawn(server);

        let (proxy_addr, proxy) = localhost_tls_proxy(SERVER_HOSTNAME, addr);
        let _proxy_handle = tokio::spawn(proxy);

        // Ensure that the proxy is doing the right thing
        let mut connector = TlsProxyConnector::new(
            DnsResolver::new_from_static_map(HashMap::from([(
                PROXY_HOSTNAME,
                LookupResult::localhost(),
            )])),
            (
                Host::Domain(PROXY_HOSTNAME.into()),
                proxy_addr.port().try_into().unwrap(),
            ),
        );
        // Override the SSL certificate for the proxy; since it's self-signed,
        // it won't work with the default config.
        let default_root_cert = std::mem::replace(
            &mut connector.proxy_certs,
            RootCertificates::FromDer(Cow::Borrowed(PROXY_CERTIFICATE.cert.der())),
        );
        assert_matches!(default_root_cert, RootCertificates::Native);

        let connection_params = TransportConnectionParams {
            sni: SERVER_HOSTNAME.into(),
            tcp_host: Host::Domain("localhost".into()),
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
                route_type: RouteType::TlsProxy,
            }
        );

        make_http_request_response_over(stream).await;
    }

    #[tokio::test]
    async fn connect_through_unencrypted_proxy() {
        let (addr, server) = localhost_http_server();
        let _server_handle = tokio::spawn(server);

        let modified_proxy_host =
            Host::Domain(format!("UNENCRYPTED_FOR_TESTING@{PROXY_HOSTNAME}").into());
        let (proxy_addr, proxy) = localhost_tcp_proxy(addr);
        let _proxy_handle = tokio::spawn(proxy);

        // Ensure that the proxy is doing the right thing
        let connector = TlsProxyConnector::new(
            DnsResolver::new_from_static_map(HashMap::from([(
                PROXY_HOSTNAME,
                LookupResult::localhost(),
            )])),
            (modified_proxy_host, proxy_addr.port().try_into().unwrap()),
        );

        let connection_params = TransportConnectionParams {
            sni: SERVER_HOSTNAME.into(),
            tcp_host: Host::Domain("localhost".into()),
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
                route_type: RouteType::TlsProxy
            }
        );

        make_http_request_response_over(stream).await;
    }
}
