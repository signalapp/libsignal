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
use libsignal_net_infra::route::{
    HttpRouteFragment, HttpsTlsRoute, TcpRoute, TlsRoute, TlsRouteFragment,
};
use libsignal_net_infra::Alpn;
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
    const HOST_IP: IpAddr = ip_addr!("1.1.1.1");

    let custom_resolver = match args.transport {
        Transport::Udp => {
            let ns_address = (HOST_IP, 53);
            Either::Left(CustomDnsResolver::<UdpTransport>::new(
                ns_address,
                &ObservableEvent::default(),
            ))
        }
        Transport::Doh => {
            let host: Arc<str> = HOST_IP.to_string().into();
            let target = HttpsTlsRoute {
                fragment: HttpRouteFragment {
                    host_header: host.clone(),
                    path_prefix: "".into(),
                    front_name: None,
                },
                inner: TlsRoute {
                    fragment: TlsRouteFragment {
                        root_certs: RootCertificates::Native,
                        sni: Host::Domain(host.clone()),
                        alpn: Some(Alpn::Http2),
                    },
                    inner: TcpRoute {
                        address: HOST_IP,
                        port: nonzero!(443u16),
                    },
                },
            };
            Either::Right(CustomDnsResolver::<DohTransport>::new(
                vec![target],
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
