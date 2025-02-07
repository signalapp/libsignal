//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use futures_util::{stream, Stream, StreamExt};
use tokio::net::UdpSocket;

use crate::dns::custom_resolver::{DnsQueryResult, DnsTransport};
use crate::dns::dns_errors::Error;
use crate::dns::dns_lookup::DnsLookupRequest;
use crate::dns::dns_message;
use crate::dns::dns_message::{parse_a_record, parse_aaaa_record, MAX_DNS_UDP_MESSAGE_LEN};
use crate::dns::dns_types::ResourceType;
use crate::{dns, DnsSource};

const A_REQUEST_ID: u16 = 0;
const AAAA_REQUEST_ID: u16 = 1;

/// DNS transport that sends queries in plaintext over UDP
#[derive(Clone, Debug)]
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
}

impl DnsTransport for UdpTransport {
    type ConnectionParameters = (IpAddr, u16);

    fn dns_source() -> DnsSource {
        DnsSource::UdpLookup
    }

    async fn connect(
        connection_params: Self::ConnectionParameters,
        ipv6_enabled: bool,
    ) -> dns::Result<UdpTransport> {
        let local_addr = match connection_params.0 {
            IpAddr::V4(_) => (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) if !ipv6_enabled => return Err(Error::TransportRestricted),
            IpAddr::V6(_) => (IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(local_addr).await?;
        socket.connect(connection_params).await?;
        Ok(UdpTransport {
            socket: Arc::new(socket),
        })
    }

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
