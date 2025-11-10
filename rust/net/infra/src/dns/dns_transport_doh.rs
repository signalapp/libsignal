//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use const_str::ip_addr;
use futures_util::Stream;
use futures_util::stream::FuturesUnordered;
use http::uri::PathAndQuery;
use http::{HeaderValue, Method};

use crate::dns::custom_resolver::{DnsQueryResult, DnsTransport};
use crate::dns::dns_errors::Error;
use crate::dns::dns_lookup::DnsLookupRequest;
use crate::dns::dns_message;
use crate::dns::dns_message::{parse_a_record, parse_aaaa_record};
use crate::dns::dns_types::ResourceType;
use crate::errors::{LogSafeDisplay, TransportConnectError};
use crate::http_client::{AggregatingHttp2Client, Http2Connector, HttpConnectError};
use crate::route::{
    Connector, ConnectorExt, ConnectorFactory, HttpsTlsRoute, TcpRoute, ThrottlingConnector,
    TlsRoute, VariableTlsTimeoutConnector,
};
use crate::timeouts::MIN_TLS_HANDSHAKE_TIMEOUT;
use crate::{DnsSource, dns};

pub(crate) const CLOUDFLARE_IPS: (Ipv4Addr, Ipv6Addr) = (
    ip_addr!(v4, "1.1.1.1"),
    ip_addr!(v6, "2606:4700:4700::1111"),
);
const MAX_RESPONSE_SIZE: usize = 10240;

pub struct DohTransportConnectorFactory;

impl ConnectorFactory<HttpsTlsRoute<TlsRoute<TcpRoute<IpAddr>>>> for DohTransportConnectorFactory {
    type Connector = DohTransportConnector;
    type Connection = DohTransport;

    fn make(&self) -> Self::Connector {
        Default::default()
    }
}

pub struct DohTransportConnector {
    transport_connector: VariableTlsTimeoutConnector<
        ThrottlingConnector<crate::tcp_ssl::StatelessTls>,
        crate::tcp_ssl::StatelessTcp,
        TransportConnectError,
    >,
}

impl Default for DohTransportConnector {
    fn default() -> Self {
        Self {
            transport_connector: VariableTlsTimeoutConnector::new(
                ThrottlingConnector::new(crate::tcp_ssl::StatelessTls, 1),
                crate::tcp_ssl::StatelessTcp,
                MIN_TLS_HANDSHAKE_TIMEOUT,
            ),
        }
    }
}

impl Connector<HttpsTlsRoute<TlsRoute<TcpRoute<IpAddr>>>, ()> for DohTransportConnector {
    type Connection = DohTransport;
    type Error = Error;

    async fn connect_over(
        &self,
        _over: (),
        route: HttpsTlsRoute<TlsRoute<TcpRoute<IpAddr>>>,
        log_tag: &str,
    ) -> Result<Self::Connection, Self::Error> {
        let connector =
            crate::route::ComposedConnector::new(Http2Connector::new(), &self.transport_connector);
        let http_client =
            connector
                .connect(route, log_tag)
                .await
                .map_err(|e: HttpConnectError| {
                    log::warn!(
                        "[{log_tag}] Failed to create HTTP2 client for DNS lookup: {}",
                        &e as &dyn LogSafeDisplay
                    );
                    Error::TransportFailure
                })?;
        Ok(DohTransport {
            http_client: AggregatingHttp2Client::new(http_client, MAX_RESPONSE_SIZE),
        })
    }
}

/// DNS transport that sends queries over HTTPS
#[derive(Clone, Debug)]
pub struct DohTransport {
    http_client: AggregatingHttp2Client,
}

impl DnsTransport for DohTransport {
    const SOURCE: DnsSource = DnsSource::DnsOverHttpsLookup;

    async fn send_queries(
        self,
        request: DnsLookupRequest,
    ) -> dns::Result<impl Stream<Item = dns::Result<DnsQueryResult>> + Send + 'static> {
        let futures = request
            .ipv6_enabled
            .then(|| {
                self.clone()
                    .send_request(request.clone(), ResourceType::AAAA)
            })
            .into_iter()
            .chain([self.send_request(request, ResourceType::A)]);
        Ok(FuturesUnordered::from_iter(futures))
    }
}

impl DohTransport {
    async fn send_request(
        mut self,
        request: DnsLookupRequest,
        resource_type: ResourceType,
    ) -> dns::Result<DnsQueryResult> {
        // In DoH, responses are correlated with requests via HTTP,
        // so request ID should always be 0
        // https://datatracker.ietf.org/doc/html/rfc8484#section-4.1
        let request_message =
            dns_message::create_request_with_id(0, &request.hostname, resource_type)?;

        let (response_parts, response_body) = self
            .http_client
            .send_request_aggregate_response(
                PathAndQuery::from_static("/dns-query"),
                Method::POST,
                [
                    (http::header::ACCEPT, "application/dns-message"),
                    (http::header::CONTENT_TYPE, "application/dns-message"),
                ]
                .map(|(header, value)| (header, HeaderValue::from_static(value)))
                .into_iter()
                .collect(),
                Bytes::from(request_message),
            )
            .await
            .map_err(|_| Error::TransportFailure)?;

        if response_parts.status.as_u16() != 200 {
            return Err(Error::DohRequestBadStatus(response_parts.status.as_u16()));
        }
        let result = match resource_type {
            ResourceType::A => DnsQueryResult::Left(dns_message::parse_response(
                &response_body,
                ResourceType::A,
                parse_a_record,
            )?),
            ResourceType::AAAA => DnsQueryResult::Right(dns_message::parse_response(
                &response_body,
                ResourceType::AAAA,
                parse_aaaa_record,
            )?),
        };
        Ok(result)
    }
}
