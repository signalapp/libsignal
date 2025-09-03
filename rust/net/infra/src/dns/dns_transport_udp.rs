//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::IpAddr;
use std::sync::Arc;

use futures_util::{Stream, StreamExt, stream};
use tokio::net::UdpSocket;

use crate::dns::custom_resolver::{DnsQueryResult, DnsTransport};
use crate::dns::dns_errors::Error;
use crate::dns::dns_lookup::DnsLookupRequest;
use crate::dns::dns_message;
use crate::dns::dns_message::{MAX_DNS_UDP_MESSAGE_LEN, parse_a_record, parse_aaaa_record};
use crate::dns::dns_types::ResourceType;
use crate::route::{
    Connector, ConnectorExt as _, ConnectorFactory, StatelessUdpConnector, UdpRoute,
};
use crate::{DnsSource, dns};

const A_REQUEST_ID: u16 = 0;
const AAAA_REQUEST_ID: u16 = 1;

pub struct UdpTransportConnectorFactory;

impl ConnectorFactory<UdpRoute<IpAddr>> for UdpTransportConnectorFactory {
    type Connector = UdpTransportConnector;
    type Connection = UdpTransport;

    fn make(&self) -> Self::Connector {
        Default::default()
    }
}

#[derive(Default)]
pub struct UdpTransportConnector;

impl Connector<UdpRoute<IpAddr>, ()> for UdpTransportConnector {
    type Connection = UdpTransport;
    type Error = Error;

    async fn connect_over(
        &self,
        _over: (),
        route: UdpRoute<IpAddr>,
        log_tag: &str,
    ) -> Result<Self::Connection, Self::Error> {
        let socket = StatelessUdpConnector
            .connect(route, log_tag)
            .await
            .map_err(|e| {
                log::warn!(
                    "[{log_tag}] Failed to create UDP socket for DNS lookup: {}",
                    e.kind()
                );
                Error::TransportFailure
            })?;
        Ok(UdpTransport {
            socket: socket.into(),
        })
    }
}

/// DNS transport that sends queries in plaintext over UDP
#[derive(Clone, Debug)]
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
}

impl DnsTransport for UdpTransport {
    const SOURCE: DnsSource = DnsSource::UdpLookup;

    async fn send_queries(
        self,
        request: DnsLookupRequest,
    ) -> dns::Result<impl Stream<Item = dns::Result<DnsQueryResult>> + Send + 'static> {
        let arc = Arc::new(self);
        let mut futures = vec![];

        // only sending AAAA request and adding a result future if `ipv6_enabled`
        if request.ipv6_enabled {
            arc.send_request(&request.hostname, AAAA_REQUEST_ID, ResourceType::AAAA)
                .await?;
            futures.push(arc.clone().next_dns_query_result1());
        }

        // always sending A request
        arc.send_request(&request.hostname, A_REQUEST_ID, ResourceType::A)
            .await?;
        futures.push(arc.clone().next_dns_query_result1());
        Ok(stream::iter(futures).then(|task| task))
    }
}

impl UdpTransport {
    async fn next_dns_query_result1(self: Arc<Self>) -> dns::Result<DnsQueryResult> {
        let mut buf = [0; MAX_DNS_UDP_MESSAGE_LEN];
        let bytes_received = self.socket.recv(&mut buf).await?;
        let message = &buf[..bytes_received];
        let result = match dns_message::get_id(message)? {
            A_REQUEST_ID => DnsQueryResult::Left(dns_message::parse_response(
                message,
                ResourceType::A,
                parse_a_record,
            )?),
            AAAA_REQUEST_ID => DnsQueryResult::Right(dns_message::parse_response(
                message,
                ResourceType::AAAA,
                parse_aaaa_record,
            )?),
            _ => Err(Error::UnexpectedMessageId)?,
        };
        Ok(result)
    }

    async fn send_request(
        &self,
        hostname: &str,
        request_id: u16,
        resource_type: ResourceType,
    ) -> dns::Result<()> {
        let request = dns_message::create_request_with_id(request_id, hostname, resource_type)?;
        let udp_message = match request {
            data if data.len() > MAX_DNS_UDP_MESSAGE_LEN => Err(Error::MessageTooLong),
            data => Ok(data),
        }?;
        let _bytes_sent = self.socket.send(udp_message.as_slice()).await?;
        Ok(())
    }
}
