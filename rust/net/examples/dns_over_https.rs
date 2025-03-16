//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;

use clap::Parser;
use futures_util::StreamExt;
use libsignal_net::infra::certs::RootCertificates;
use libsignal_net::infra::dns::custom_resolver::DnsTransport;
use libsignal_net::infra::dns::dns_lookup::DnsLookupRequest;
use libsignal_net::infra::dns::dns_transport_doh::DohTransport;
use libsignal_net::infra::host::Host;
use libsignal_net_infra::route::{
    HttpRouteFragment, HttpsTlsRoute, TcpRoute, TlsRoute, TlsRouteFragment,
};
use libsignal_net_infra::Alpn;

#[derive(Parser, Debug)]
struct Args {
    /// disable IPv6 address group
    #[arg(long, default_value = "false")]
    no_ipv6: bool,
    /// domain to lookup
    #[arg(long, default_value = "chat.signal.org")]
    domain: String,
    /// address of the name server
    #[arg(long, default_value = "1.1.1.1")]
    ns_address: IpAddr,
    /// port of the name server
    #[arg(long, default_value = "443")]
    ns_port: NonZeroU16,
}

#[tokio::main]
async fn main() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init();

    let args = Args::parse();
    let address = args.ns_address;

    let host: Arc<str> = address.to_string().into();
    let route = HttpsTlsRoute {
        fragment: HttpRouteFragment {
            host_header: host.clone(),
            path_prefix: "".into(),
            front_name: None,
        },
        inner: TlsRoute {
            fragment: TlsRouteFragment {
                root_certs: RootCertificates::Native,
                sni: Host::Domain(host),
                alpn: Some(Alpn::Http2),
            },
            inner: TcpRoute {
                address,
                port: args.ns_port,
            },
        },
    };

    let doh_transport = DohTransport::connect(vec![route.clone()], !args.no_ipv6)
        .await
        .expect("connected to the DNS server");
    log::info!("successfully connected to the DNS server at {:?}", route);

    let request = DnsLookupRequest {
        hostname: Arc::from(args.domain),
        ipv6_enabled: !args.no_ipv6,
    };
    log::info!("sending DNS request: {:?}", request);
    let mut stream = doh_transport.send_queries(request).await.unwrap();

    let next_response = stream.next().await;
    log::info!("received first response from DNS: [{:?}]", next_response);

    let next_response = stream.next().await;
    log::info!("received second response from DNS: [{:?}]", next_response);
}
