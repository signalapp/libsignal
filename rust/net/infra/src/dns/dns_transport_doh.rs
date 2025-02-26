//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use bytes::Bytes;
use const_str::ip_addr;
use futures_util::stream::FuturesUnordered;
use futures_util::Stream;
use http::uri::PathAndQuery;
use http::{HeaderValue, Method};

use crate::dns::custom_resolver::{DnsQueryResult, DnsTransport};
use crate::dns::dns_errors::Error;
use crate::dns::dns_lookup::DnsLookupRequest;
use crate::dns::dns_message;
use crate::dns::dns_message::{parse_a_record, parse_aaaa_record};
use crate::dns::dns_types::ResourceType;
use crate::http_client::{http2_client, AggregatingHttp2Client};
use crate::route::{HttpsTlsRoute, TcpRoute, TlsRoute};
use crate::{dns, DnsSource};

pub(crate) const CLOUDFLARE_IPS: (Ipv4Addr, Ipv6Addr) = (
    ip_addr!(v4, "1.1.1.1"),
    ip_addr!(v6, "2606:4700:4700::1111"),
);
const MAX_RESPONSE_SIZE: usize = 10240;

/// DNS transport that sends queries over HTTPS
#[derive(Clone, Debug)]
pub struct DohTransport {
    http_client: AggregatingHttp2Client,
}

impl DnsTransport for DohTransport {
    type ConnectionParameters = Vec<HttpsTlsRoute<TlsRoute<TcpRoute<IpAddr>>>>;

    fn dns_source() -> DnsSource {
        DnsSource::DnsOverHttpsLookup
    }

    async fn connect(
        connection_params: Self::ConnectionParameters,
        _ipv6_enabled: bool,
    ) -> dns::Result<Self> {
        let log_tag = "DNS-over-HTTPS".into();
        match http2_client(connection_params, MAX_RESPONSE_SIZE, &log_tag).await {
            Ok(http_client) => Ok(Self { http_client }),
            Err(error) => {
                log::error!("[{log_tag}] Failed to create HTTP2 client: {error}");
                Err(Error::TransportFailure)
            }
        }
    }

    async fn send_queries(
        self,
        request: DnsLookupRequest,
    ) -> dns::Result<impl Stream<Item = dns::Result<DnsQueryResult>> + Send + 'static> {
        let arc = Arc::new(self);
        let futures = match request.ipv6_enabled {
            true => vec![
                arc.clone()
                    .send_request(request.clone(), ResourceType::AAAA),
                arc.clone().send_request(request.clone(), ResourceType::A),
            ],
            false => vec![arc.clone().send_request(request.clone(), ResourceType::A)],
        };
        Ok(FuturesUnordered::from_iter(futures))
    }
}

impl DohTransport {
    async fn send_request(
        self: Arc<Self>,
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
