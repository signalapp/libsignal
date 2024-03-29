//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use boring::ssl::{SslConnector, SslConnectorBuilder, SslMethod};
use futures_util::TryFutureExt;
use tokio::net::TcpStream;
use tokio_boring::SslStream;

use crate::infra::certs::RootCertificates;
use crate::infra::dns::DnsResolver;
use crate::infra::errors::TransportConnectError;
use crate::infra::{Alpn, ConnectionInfo, ConnectionParams, StreamAndInfo, TransportConnector};
use crate::utils::first_ok;

const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(200);

#[derive(Clone)]
pub struct TcpSslTransportConnector {
    dns_resolver: Arc<DnsResolver>,
}

#[async_trait]
impl TransportConnector for TcpSslTransportConnector {
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

        let ssl_config = Self::builder(connection_params.certs, alpn)?
            .build()
            .configure()?;

        let ssl_stream =
            tokio_boring::connect(ssl_config, &connection_params.sni, tcp_stream).await?;

        Ok(StreamAndInfo(ssl_stream, remote_address))
    }
}

impl TcpSslTransportConnector {
    pub fn new(resolver: DnsResolver) -> Self {
        Self {
            dns_resolver: Arc::new(resolver),
        }
    }

    fn builder(
        certs: RootCertificates,
        alpn: Alpn,
    ) -> Result<SslConnectorBuilder, TransportConnectError> {
        let mut ssl = SslConnector::builder(SslMethod::tls_client())?;
        ssl.set_verify_cert_store(certs.try_into()?)?;
        ssl.set_alpn_protos(alpn.as_ref())?;
        Ok(ssl)
    }
}

pub(crate) async fn connect_tcp(
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

#[cfg(test)]
mod test {
    use std::net::Ipv6Addr;

    use lazy_static::lazy_static;
    use rcgen::CertifiedKey;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use warp::Filter;

    use crate::infra::HttpRequestDecoratorSeq;

    use super::*;

    const TEST_SNI: &str = "localhost";

    lazy_static! {
        static ref CERTIFICATE: CertifiedKey =
            rcgen::generate_simple_self_signed([TEST_SNI.to_string()]).expect("can generate");
    }

    #[tokio::test]
    async fn connect_to_server() {
        const FAKE_RESPONSE: &str = "Hello there";

        let filter = warp::any().map(|| FAKE_RESPONSE);
        let server = warp::serve(filter)
            .tls()
            .cert(CERTIFICATE.cert.pem())
            .key(CERTIFICATE.key_pair.serialize_pem());

        let (addr, server) = server.bind_ephemeral((Ipv6Addr::LOCALHOST, 0));
        let _server_handle = tokio::spawn(server);

        let connector = TcpSslTransportConnector::new(DnsResolver::default());
        let connection_params = ConnectionParams {
            route_type: "test",
            sni: TEST_SNI.into(),
            host: addr.ip().to_string().into(),
            port: addr.port().try_into().expect("bound port"),
            http_request_decorator: HttpRequestDecoratorSeq::default(),
            certs: RootCertificates::FromDer(CERTIFICATE.cert.der()),
        };

        let StreamAndInfo(mut stream, info) = connector
            .connect(&connection_params, Alpn::Http1_1)
            .await
            .expect("can connect");

        assert_eq!(
            info,
            ConnectionInfo {
                address: url::Host::Ipv6(Ipv6Addr::LOCALHOST),
                dns_source: crate::infra::DnsSource::Lookup,
                route_type: "test"
            }
        );

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
