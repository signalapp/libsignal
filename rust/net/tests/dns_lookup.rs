//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Non-hermetic tests to make sure DNS lookups work.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use const_str::ip_addr;
use itertools::Itertools;
use libsignal_net_infra::dns::build_custom_resolver_cloudflare_doh;
use libsignal_net_infra::dns::custom_resolver::CustomDnsResolver;
use libsignal_net_infra::dns::dns_lookup::{DnsLookup, DnsLookupRequest, SystemDnsLookup};
use libsignal_net_infra::dns::dns_transport_udp::UdpTransportConnectorFactory;
use libsignal_net_infra::route::UdpRoute;
use libsignal_net_infra::timeouts::DNS_LATER_RESPONSE_GRACE_PERIOD;
use libsignal_net_infra::utils::no_network_change_events;
use nonzero_ext::nonzero;

macro_rules! skip_unless_nonhermetic {
    () => {
        if std::env::var("LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS").is_err() {
            println!("SKIPPED: running integration tests is not enabled");
            return;
        }
    };
}

#[tokio::test]
async fn system_dns_lookup() {
    let dns = SystemDnsLookup;
    let result = dns
        .dns_lookup(DnsLookupRequest {
            hostname: "localhost".into(),
            ipv6_enabled: true,
        })
        .await
        .expect("can look up");
    assert_eq!(
        result.into_iter().collect_vec(),
        vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ]
    );
}

#[tokio::test]
async fn udp_dns_lookup() {
    skip_unless_nonhermetic!();
    let dns = CustomDnsResolver::new(
        vec![UdpRoute {
            address: ip_addr!("1.1.1.1"),
            port: nonzero!(53u16),
        }],
        UdpTransportConnectorFactory,
        &no_network_change_events(),
        DNS_LATER_RESPONSE_GRACE_PERIOD,
    );

    let result = dns
        .resolve(DnsLookupRequest {
            hostname: "signal.org".into(),
            ipv6_enabled: true,
        })
        .await
        .expect("can look up");

    println!("found {result:?}");
    let (v4, v6): (Vec<_>, Vec<_>) = result.into_iter().partition(IpAddr::is_ipv4);
    assert!(!v4.is_empty());
    assert!(!v6.is_empty());
}

#[tokio::test]
async fn dns_over_https_lookup() {
    skip_unless_nonhermetic!();
    let dns = build_custom_resolver_cloudflare_doh(
        &no_network_change_events(),
        // Don't time out the second request early since we're asserting on the
        // presence of both responses.
        Duration::MAX,
    );

    let result = dns
        .resolve(DnsLookupRequest {
            hostname: "signal.org".into(),
            ipv6_enabled: true,
        })
        .await
        .expect("can look up");

    println!("found {result:?}");
    let (v4, v6): (Vec<_>, Vec<_>) = result.into_iter().partition(IpAddr::is_ipv4);
    assert!(!v4.is_empty());
    assert!(!v6.is_empty());
}
