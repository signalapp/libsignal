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

use crate::infra::certs::RootCertificates;
use crate::infra::dns::DnsResolver;
use crate::infra::errors::TransportConnectError;
use crate::infra::tcp_ssl::{connect_tcp, connect_tls, ssl_config};
use crate::infra::{
    Alpn, ConnectionInfo, ConnectionParams, RouteType, StreamAndInfo, TransportConnector,
};

/// A [`TransportConnector`] that proxies through a TLS server.
///
/// The proxy server should expose a listening port. If `use_tls_for_proxy` is
/// [`ShouldUseTls::Yes`], the port should accept TLS client connections;
/// otherwise unencrypted. The proxy will transparently proxy TLS traffic by
/// examining the SNI of incoming connections to determine the destination host.
///
/// An example implementation of such a target service can be found at
/// https://github.com/signalapp/Signal-TLS-Proxy.
#[derive(Clone)]
pub struct TlsProxyConnector {
    pub dns_resolver: DnsResolver,
    proxy_host: Arc<str>,
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

        let inner_stream = match self.use_tls_for_proxy {
            ShouldUseTls::Yes => {
                log::debug!(
                    "connecting to proxy {}:{}",
                    self.proxy_host,
                    self.proxy_port
                );
                let ssl_config = ssl_config(&self.proxy_certs, &self.proxy_host, None)?;
                Either::Left(
                    tokio_boring_signal::connect(ssl_config, &self.proxy_host, tcp_stream).await?,
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

        let tls_stream = connect_tls(inner_stream, connection_params, alpn).await?;

        Ok(StreamAndInfo(
            tls_stream,
            ConnectionInfo {
                route_type: RouteType::TlsProxy,
                ..remote_address
            },
        ))
    }
}

impl TlsProxyConnector {
    pub fn new(dns_resolver: DnsResolver, (proxy_host, proxy_port): (&str, NonZeroU16)) -> Self {
        let (use_tls_for_proxy, actual_host) = Self::parse_host_for_tls_opt_out(proxy_host);

        Self {
            dns_resolver,
            proxy_host: actual_host.into(),
            proxy_port,
            // We don't bundle roots of trust for all the SSL proxies, just the
            // Signal servers. It's fine to use the system SSL trust roots;
            // even if the outer connection is not secure, the inner connection
            // is also TLS-encrypted.
            proxy_certs: RootCertificates::Native,
            use_tls_for_proxy,
        }
    }

    pub fn set_proxy(&mut self, (host, port): (&str, NonZeroU16)) {
        let (use_tls_for_proxy, actual_host) = Self::parse_host_for_tls_opt_out(host);

        self.proxy_host = actual_host.into();
        self.proxy_port = port;
        self.use_tls_for_proxy = use_tls_for_proxy;
    }

    fn parse_host_for_tls_opt_out(proxy_host: &str) -> (ShouldUseTls, &str) {
        // Special case for testing: UNENCRYPTED_FOR_TESTING@foo.bar connects over TCP instead of TLS.
        if let Some(("UNENCRYPTED_FOR_TESTING", host)) = proxy_host.split_once('@') {
            (ShouldUseTls::No, host)
        } else {
            (ShouldUseTls::Yes, proxy_host)
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::super::testutil::*;
    use super::*;

    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::net::Ipv6Addr;

    use assert_matches::assert_matches;

    use crate::infra::dns::lookup_result::LookupResult;
    use crate::infra::tcp_ssl::proxy::testutil::{
        localhost_tcp_proxy, localhost_tls_proxy, PROXY_CERTIFICATE, PROXY_HOSTNAME,
    };
    use crate::infra::HttpRequestDecoratorSeq;

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
            (PROXY_HOSTNAME, proxy_addr.port().try_into().unwrap()),
        );
        // Override the SSL certificate for the proxy; since it's self-signed,
        // it won't work with the default config.
        let default_root_cert = std::mem::replace(
            &mut connector.proxy_certs,
            RootCertificates::FromDer(Cow::Borrowed(PROXY_CERTIFICATE.cert.der())),
        );
        assert_matches!(default_root_cert, RootCertificates::Native);

        let connection_params = ConnectionParams {
            route_type: RouteType::Test,
            sni: SERVER_HOSTNAME.into(),
            host: "localhost".to_string().into(),
            port: addr.port().try_into().expect("bound port"),
            http_request_decorator: HttpRequestDecoratorSeq::default(),
            certs: RootCertificates::FromDer(Cow::Borrowed(SERVER_CERTIFICATE.cert.der())),
            connection_confirmation_header: None,
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
                route_type: RouteType::TlsProxy,
            }
        );

        make_http_request_response_over(stream).await;
    }

    #[tokio::test]
    async fn connect_through_unencrypted_proxy() {
        let (addr, server) = localhost_http_server();
        let _server_handle = tokio::spawn(server);

        let modified_proxy_host = format!("UNENCRYPTED_FOR_TESTING@{PROXY_HOSTNAME}");
        let (proxy_addr, proxy) = localhost_tcp_proxy(addr);
        let _proxy_handle = tokio::spawn(proxy);

        // Ensure that the proxy is doing the right thing
        let connector = TlsProxyConnector::new(
            DnsResolver::new_from_static_map(HashMap::from([(
                PROXY_HOSTNAME,
                LookupResult::localhost(),
            )])),
            (&modified_proxy_host, proxy_addr.port().try_into().unwrap()),
        );

        let connection_params = ConnectionParams {
            route_type: RouteType::Test,
            sni: SERVER_HOSTNAME.into(),
            host: "localhost".to_string().into(),
            port: addr.port().try_into().expect("bound port"),
            http_request_decorator: HttpRequestDecoratorSeq::default(),
            certs: RootCertificates::FromDer(Cow::Borrowed(SERVER_CERTIFICATE.cert.der())),
            connection_confirmation_header: None,
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
                route_type: RouteType::TlsProxy
            }
        );

        make_http_request_response_over(stream).await;
    }
}
