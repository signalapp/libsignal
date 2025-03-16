//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use clap::Parser;
use futures_util::StreamExt;
use libsignal_net::infra::dns::custom_resolver::DnsTransport;
use libsignal_net::infra::dns::dns_lookup::DnsLookupRequest;
use libsignal_net::infra::dns::dns_transport_udp::UdpTransport;

#[derive(Parser, Debug)]
struct Args {
    /// is IPv6 address group enabled
    #[arg(long, default_value = "false")]
    no_ipv6: bool,
    /// domain to lookup
    #[arg(long, default_value = "chat.signal.org")]
    domain: String,
    /// address of the name server
    #[arg(long, default_value = "1.1.1.1")]
    ns_address: String,
    /// port of the name server
    #[arg(long, default_value = "53")]
    ns_port: u16,
}

#[tokio::main]
async fn main() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .try_init();

    let args = Args::parse();

    let ns_address = (
        IpAddr::from_str(args.ns_address.as_str()).expect("valid IP address"),
        args.ns_port,
    );

    let udp_transport = UdpTransport::connect(ns_address, !args.no_ipv6)
        .await
        .expect("connected to the DNS server");
    log::info!(
        "successfully connected to the DNS server at {:?}",
        ns_address
    );

    let request = DnsLookupRequest {
        hostname: Arc::from(args.domain.as_str()),
        ipv6_enabled: !args.no_ipv6,
    };
    log::info!("sending DNS request: {:?}", request);
    let mut stream = udp_transport.send_queries(request).await.unwrap();
    let mut stream = std::pin::pin!(stream);

    let next_response = stream.next().await;
    log::info!("received first response from DNS: [{:?}]", next_response);

    let next_response = stream.next().await;
    log::info!("received second response from DNS: [{:?}]", next_response);
}
