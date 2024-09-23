//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::net::IpAddr;
use std::sync::Arc;

use clap::{Parser, ValueEnum};
use const_str::ip_addr;
use either::{for_both, Either};
use libsignal_net::infra::certs::RootCertificates;
use libsignal_net::infra::dns::custom_resolver::CustomDnsResolver;
use libsignal_net::infra::dns::dns_lookup::{DnsLookup, DnsLookupRequest};
use libsignal_net::infra::dns::dns_transport_doh::DohTransport;
use libsignal_net::infra::dns::dns_transport_udp::UdpTransport;
use libsignal_net::infra::host::Host;
use libsignal_net::infra::utils::ObservableEvent;
use libsignal_net::infra::{
    ConnectionParams, HttpRequestDecoratorSeq, RouteType, TransportConnectionParams,
};
use nonzero_ext::nonzero;
use tokio::time::Instant;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Transport {
    /// Send plaintext request over UDP
    Udp,
    /// Send DNS-over-HTTPS request
    Doh,
}

#[derive(Parser, Debug)]
struct Args {
    /// name server to use
    #[arg(long)]
    transport: Transport,
    /// domain name to resolve
    #[arg(long)]
    domain: String,
}

#[tokio::main]
async fn main() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init();

    let args = Args::parse();

    let custom_resolver = match args.transport {
        Transport::Udp => {
            let ns_address = (IpAddr::V4(ip_addr!(v4, "1.1.1.1")), 53);
            Either::Left(CustomDnsResolver::<UdpTransport>::new(
                ns_address,
                &ObservableEvent::default(),
            ))
        }
        Transport::Doh => {
            let host = "1.1.1.1".into();
            let connection_params = ConnectionParams {
                route_type: RouteType::Direct,
                http_request_decorator: HttpRequestDecoratorSeq::default(),
                connection_confirmation_header: None,
                transport: TransportConnectionParams {
                    sni: Arc::clone(&host),
                    tcp_host: Host::Ip(ip_addr!("1.1.1.1")),
                    port: nonzero!(443u16),
                    certs: RootCertificates::Native,
                },
                http_host: host,
            };
            Either::Right(CustomDnsResolver::<DohTransport>::new(
                connection_params,
                &ObservableEvent::default(),
            ))
        }
    };

    let lookup_request = DnsLookupRequest {
        hostname: Arc::from(args.domain.as_str()),
        ipv6_enabled: true,
    };

    // first time making a DNS query
    let started_at = Instant::now();
    let result = for_both!(custom_resolver, ref c => c.dns_lookup(lookup_request.clone()).await);
    log::info!(
        "DNS lookup result for [{}] after {:?}: {:?}",
        args.domain,
        started_at.elapsed(),
        result
    );

    // second time retrieving from cache
    let started_at = Instant::now();
    let result = for_both!(custom_resolver, ref c => c.dns_lookup(lookup_request.clone()).await);
    log::info!(
        "DNS lookup result for [{}] after {:?}: {:?}",
        args.domain,
        started_at.elapsed(),
        result
    );
}
