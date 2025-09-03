//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::{HashMap, HashSet};

use assert_matches::assert_matches;
use async_trait::async_trait;
use futures_util::{StreamExt as _, TryFutureExt as _};
use itertools::Itertools as _;
use libsignal_net::chat;
use libsignal_net::env::{DomainConfig, STAGING};
use libsignal_net::infra::errors::TransportConnectError;
use libsignal_net_infra::dns::dns_lookup::{DnsLookup, DnsLookupRequest};
use libsignal_net_infra::dns::lookup_result::LookupResult;
use libsignal_net_infra::dns::{self, DnsResolver};
use libsignal_net_infra::host::Host;
use libsignal_net_infra::route::PER_CONNECTION_WAIT_DURATION;
use libsignal_net_infra::timeouts::{MIN_TLS_HANDSHAKE_TIMEOUT, TCP_CONNECTION_TIMEOUT};
use libsignal_net_infra::utils::timed;
use test_case::test_case;
use tokio::time::{Duration, Instant};

mod fake_transport;
use fake_transport::{
    FakeDeps, allow_domain_fronting, connect_websockets_on_incoming, error_all_hosts_after,
    only_direct_routes,
};

use crate::fake_transport::{
    Behavior, FakeTransportTarget, TransportConnectEvent, TransportConnectEventStage,
    allow_all_routes,
};

#[test_log::test(tokio::test(start_paused = true))]
async fn all_routes_connect_hangs_forever() {
    // Connection attempt timing in libsignal-net:
    //
    // Routes are attempted with staggered start times to avoid overwhelming the network.
    // Each new connection attempt is delayed based on the number of in-flight connections
    // using the formula: delay = PER_CONNECTION_WAIT_DURATION * connections_in_progress
    //
    // For the staging configuration with 3 routes:
    // - Route 1: Starts at t=0ms (no delay, no connections in progress)
    // - Route 2: Starts at t=500ms (delayed by 500ms × 1 connection in progress)
    // - Route 3: Starts at t=1500ms (starts 1000ms after Route 2, due to 500ms × 2 connections in progress)
    //
    // With DelayForever behavior, all TCP connections hang until TCP_CONNECTION_TIMEOUT (15s).
    // The final route (Route 3) times out at: 1500ms + 15000ms = 16500ms
    const EXPECTED_DURATION: Duration = PER_CONNECTION_WAIT_DURATION
        .checked_mul(3)
        .unwrap()
        .checked_add(TCP_CONNECTION_TIMEOUT)
        .unwrap();
    let (deps, _incoming_streams) = FakeDeps::new(&STAGING.chat_domain_config);

    let (elapsed, outcome) = timed(deps.connect_chat().map_ok(|_| ())).await;

    assert_eq!(elapsed, EXPECTED_DURATION);
    assert_matches!(outcome, Err(chat::ConnectError::AllAttemptsFailed));
}

#[test_case(Duration::from_millis(500))]
#[test_log::test(tokio::test(start_paused = true))]
async fn only_proxies_are_reachable(expected_duration: Duration) {
    let (deps, incoming_streams) = FakeDeps::new(&STAGING.chat_domain_config);
    deps.transport_connector
        .set_behaviors(allow_domain_fronting(
            &STAGING.chat_domain_config,
            deps.static_ip_map(),
        ));

    tokio::spawn(connect_websockets_on_incoming(incoming_streams));

    let (elapsed, outcome) = timed(deps.connect_chat().map_ok(|_| ())).await;

    assert_matches!(outcome, Ok(_));
    assert_eq!(elapsed, expected_duration);
}

#[test_case(Duration::from_millis(500))]
#[test_log::test(tokio::test(start_paused = true))]
async fn direct_connect_fails_after_30s_but_proxies_reachable(expected_duration: Duration) {
    let (deps, incoming_streams) = FakeDeps::new(&STAGING.chat_domain_config);
    deps.transport_connector.set_behaviors(
        error_all_hosts_after(
            &STAGING.chat_domain_config,
            deps.static_ip_map(),
            Duration::from_secs(30),
            || TransportConnectError::TcpConnectionFailed,
        )
        .chain(allow_domain_fronting(
            &STAGING.chat_domain_config,
            deps.static_ip_map(),
        )),
    );
    tokio::spawn(connect_websockets_on_incoming(incoming_streams));

    let (elapsed, outcome) = timed(deps.connect_chat().map_ok(|_| ())).await;

    assert_eq!(elapsed, expected_duration);
    assert_matches!(outcome, Ok(_));
}

#[test_case(Duration::from_secs(60))]
#[test_log::test(tokio::test(start_paused = true))]

async fn transport_connects_but_websocket_never_responds(expected_duration: Duration) {
    let chat_domain_config = STAGING.chat_domain_config;
    let (deps, incoming_streams) = FakeDeps::new(&chat_domain_config);
    deps.transport_connector
        .set_behaviors(allow_all_routes(&chat_domain_config, deps.static_ip_map()));

    let (elapsed, outcome) = timed(deps.connect_chat().map_ok(|_| ())).await;

    // Now that the connect attempt is done, collect (and close) the incoming streams.
    // (If we did this concurrently, the connection logic would move on to the next route.)
    // Note that we have to guarantee there won't be any more connection attempts for collect()!
    drop(deps);
    let incoming_stream_hosts: Vec<_> =
        incoming_streams.map(|(host, _stream)| host).collect().await;

    assert_eq!(elapsed, expected_duration);
    assert_matches!(outcome, Err(chat::ConnectError::Timeout));

    assert_eq!(
        &incoming_stream_hosts,
        &[Host::Domain(chat_domain_config.connect.hostname.into())],
        "should only have one websocket connection"
    );
}

#[test_case(Duration::from_millis(500), Duration::from_millis(500))]
#[test_log::test(tokio::test(start_paused = true))]
async fn connect_again_skips_timed_out_routes(
    expected_first_duration: Duration,
    expected_second_duration: Duration,
) {
    let (deps, incoming_streams) = FakeDeps::new(&STAGING.chat_domain_config);

    // For this test, only the proxy targets are reachable. The connection
    // manager should "learn" from the first attempt, after which a later
    // attempt will skip those routes and connect quickly.
    deps.transport_connector
        .set_behaviors(allow_domain_fronting(
            &STAGING.chat_domain_config,
            deps.static_ip_map(),
        ));
    tokio::spawn(connect_websockets_on_incoming(incoming_streams));

    {
        let (elapsed, outcome) = timed(deps.connect_chat().map_ok(|_| ())).await;
        assert_matches!(outcome, Ok(_));
        assert_eq!(elapsed, expected_first_duration);
    }
    {
        let (elapsed, outcome) = timed(deps.connect_chat().map_ok(|_| ())).await;
        assert_matches!(outcome, Ok(_));
        assert_eq!(elapsed, expected_second_duration);
    }
}

#[test_log::test(tokio::test(start_paused = true))]
async fn runs_one_tls_handshake_at_a_time() {
    let domain_config = STAGING.chat_domain_config;
    let (deps, incoming_streams) = FakeDeps::new(&domain_config);

    // This is set to be less than MIN_TLS_HANDSHAKE_TIMEOUT, so that we don't have to otherwise
    // take the timeout into account.
    const TLS_HANDSHAKE_DELAY: Duration =
        MIN_TLS_HANDSHAKE_TIMEOUT.saturating_sub(Duration::from_millis(1));
    tokio::spawn(connect_websockets_on_incoming(incoming_streams));
    deps.transport_connector.set_behaviors(
        allow_all_routes(&domain_config, deps.static_ip_map()).map(|(target, behavior)| {
            // Pretend that TLS handshakes take a long time to complete.
            let new_behavior = match &target {
                FakeTransportTarget::Tls { .. } => Behavior::Delay {
                    delay: TLS_HANDSHAKE_DELAY,
                    then: behavior.into(),
                },
                FakeTransportTarget::TcpThroughProxy { .. } | FakeTransportTarget::Tcp { .. } => {
                    behavior
                }
            };
            (target, new_behavior)
        }),
    );

    let start = Instant::now();
    let (timing, outcome) = timed(deps.connect_chat().map_ok(|_| ())).await;
    assert_matches!(outcome, Ok(_));

    let events = deps
        .transport_connector
        .recorded_events
        .lock()
        .unwrap()
        .drain(..)
        .map(|(event, when)| (event, when.duration_since(start)))
        .collect_vec();

    const FIRST_DELAY: Duration = Duration::from_millis(500);
    const SECOND_DELAY: Duration = Duration::from_millis(1500);

    use TransportConnectEvent::*;
    use TransportConnectEventStage::*;
    assert_matches!(
        &*events,
        [
            // There are 3 successful TCP connections made but only one TLS
            // handshake is attempted. The other connections are abandoned when
            // the first TLS handshake completes, so we never see any TLS
            // handshake events for them.
            ((TcpConnect(_), Start), Duration::ZERO),
            ((TcpConnect(_), End), Duration::ZERO),
            ((TlsHandshake(Host::Domain(first_sni)), Start), Duration::ZERO),
            ((TcpConnect(_), Start), FIRST_DELAY),
            ((TcpConnect(_), End), FIRST_DELAY),
            ((TcpConnect(_), Start), SECOND_DELAY),
            ((TcpConnect(_), End), SECOND_DELAY),
            ((TlsHandshake(_), End), TLS_HANDSHAKE_DELAY),
        ] => assert_eq!(&**first_sni, STAGING.chat_domain_config.connect.hostname)
    );
    assert_eq!(timing, TLS_HANDSHAKE_DELAY);
}

#[test_case(MIN_TLS_HANDSHAKE_TIMEOUT)]
#[test_log::test(tokio::test(start_paused = true))]
async fn first_tls_hangs_then_fallback_succeeds(expected_duration: Duration) {
    const CHAT_DOMAIN_CONFIG: DomainConfig = STAGING.chat_domain_config;
    let (deps, incoming_streams) = FakeDeps::new(&CHAT_DOMAIN_CONFIG);

    // Simulate a hanging TLS handshake on the direct route (using allow_direct_routes) to force a fallback via domain fronting.
    deps.transport_connector.set_behaviors(
        only_direct_routes(&CHAT_DOMAIN_CONFIG, deps.static_ip_map())
            .map(|(target, behavior)| {
                let modified = match &target {
                    // For direct TLS handshake, force a hang.
                    FakeTransportTarget::Tls { .. } => Behavior::DelayForever,
                    _ => behavior,
                };
                (target, modified)
            })
            .chain(allow_domain_fronting(
                &CHAT_DOMAIN_CONFIG,
                deps.static_ip_map(),
            )),
    );

    tokio::spawn(connect_websockets_on_incoming(incoming_streams));

    let (elapsed, outcome) = timed(deps.connect_chat().map_ok(|_| ())).await;
    outcome.expect("expected connection to succeed via fallback route");
    assert_eq!(elapsed, expected_duration);

    use TransportConnectEvent::*;
    use TransportConnectEventStage::*;
    let tls_events = deps
        .transport_connector
        .recorded_events
        .lock()
        .unwrap()
        .drain(..)
        .map(|(event, _when)| event)
        .filter(|event| matches!(event, (TlsHandshake(..), _)))
        .collect_vec();

    const DIRECT_CHAT_DOMAIN: &str = CHAT_DOMAIN_CONFIG.connect.hostname;

    let valid_proxy_snis: HashSet<String> =
        allow_domain_fronting(&CHAT_DOMAIN_CONFIG, deps.static_ip_map())
            .filter_map(|(target, _)| match target {
                FakeTransportTarget::Tls {
                    sni: Host::Domain(sni),
                } => Some(sni.to_string()),
                _ => None,
            })
            .collect();

    assert_matches!(&tls_events[..], [
        (TlsHandshake(Host::Domain(first_sni)), Start),
        (TlsHandshake(Host::Domain(second_sni_start)), Start),
        (TlsHandshake(Host::Domain(second_sni_end)), End),
      ] => {
        assert_eq!(&**first_sni, DIRECT_CHAT_DOMAIN);
        assert_eq!(second_sni_start, second_sni_end, "The end event should be for the SNI for the handshake started second");
        assert!(valid_proxy_snis.contains(&second_sni_start.to_string()),
            "SNI '{}' should be in the valid proxy SNIs: {:?}",
            &**second_sni_start,
            valid_proxy_snis
        );
      }
    );
}

#[derive(Debug)]
struct DnsLookupThatNeverCompletes;
#[async_trait]
impl DnsLookup for DnsLookupThatNeverCompletes {
    async fn dns_lookup(
        &self,
        _request: DnsLookupRequest,
    ) -> dns::Result<dns::lookup_result::LookupResult> {
        std::future::pending().await
    }
}

#[derive(Debug)]
struct DnsLookupThatFailsSlowly(Duration);
#[async_trait]
impl DnsLookup for DnsLookupThatFailsSlowly {
    async fn dns_lookup(
        &self,
        _request: DnsLookupRequest,
    ) -> dns::Result<dns::lookup_result::LookupResult> {
        tokio::time::sleep(self.0).await;
        Err(dns::DnsError::LookupFailed)
    }
}

#[derive(Debug)]
struct DnsLookupThatRunsSlowly(Duration, HashMap<&'static str, LookupResult>);
#[async_trait]
impl DnsLookup for DnsLookupThatRunsSlowly {
    async fn dns_lookup(
        &self,
        request: DnsLookupRequest,
    ) -> dns::Result<dns::lookup_result::LookupResult> {
        tokio::time::sleep(self.0).await;
        self.1
            .get(&*request.hostname)
            .cloned()
            .ok_or(dns::DnsError::LookupFailed)
    }
}

const DNS_STRATEGY_TIMEOUT: Duration = Duration::from_secs(7);

#[test_case(DnsLookupThatNeverCompletes, DNS_STRATEGY_TIMEOUT)]
#[test_case(
    DnsLookupThatFailsSlowly(Duration::from_secs(3)),
    Duration::from_secs(3)
)]
#[test_log::test(tokio::test(start_paused = true))]
async fn custom_dns_failure(lookup: impl DnsLookup + 'static, expected_duration: Duration) {
    let chat_domain_config = STAGING.chat_domain_config;
    let (mut deps, incoming_streams) = FakeDeps::new(&chat_domain_config);
    deps.dns_resolver = DnsResolver::new_custom(vec![(Box::new(lookup), DNS_STRATEGY_TIMEOUT)]);

    // Don't do anything with the incoming transport streams, just let them
    // accumulate in the unbounded stream.
    let _ignore_incoming_streams = incoming_streams;

    let (elapsed, outcome) = timed(deps.connect_chat().map_ok(|_| ())).await;

    assert_eq!(elapsed, expected_duration);
    assert_matches!(outcome, Err(chat::ConnectError::AllAttemptsFailed));
}

#[test_case(false)]
#[test_case(true)]
#[test_log::test(tokio::test(start_paused = true))]
async fn slow_dns(should_accept_connection: bool) {
    // DNS resolution timing:
    // - DNS resolution takes 3 seconds before any routes are available
    // - After DNS completes, routes are attempted with staggered start times
    //
    // For the staging configuration with 3 routes:
    // - Route 1: Starts at t=3000ms (DNS resolution time)
    // - Route 2: Starts at t=3500ms (3000ms + 500ms × 1 connection in progress)
    // - Route 3: Starts at t=4500ms (3000ms + 1000ms, due to 500ms × 2 connections in progress)
    //
    // When should_accept_connection is true, the first route succeeds immediately, so
    //   the total duration is DNS_RESOLUTION_TIME.
    // When false, all TCP connections hang until TCP_CONNECTION_TIMEOUT (15s), so the total duration is
    //   the Route 3 start delay + TCP_CONNECTION_TIMEOUT.
    const DNS_RESOLUTION_TIME: Duration = Duration::from_secs(3);
    const EXPECTED_DURATION: Duration = DNS_RESOLUTION_TIME
        .checked_add(PER_CONNECTION_WAIT_DURATION.checked_mul(3).unwrap())
        .unwrap()
        .checked_add(TCP_CONNECTION_TIMEOUT)
        .unwrap();
    let expected_duration = if should_accept_connection {
        DNS_RESOLUTION_TIME
    } else {
        EXPECTED_DURATION
    };
    let chat_domain_config = STAGING.chat_domain_config;
    let (mut deps, incoming_streams) = FakeDeps::new(&chat_domain_config);
    deps.dns_resolver = DnsResolver::new_custom(vec![(
        Box::new(DnsLookupThatRunsSlowly(
            DNS_RESOLUTION_TIME,
            deps.static_ip_map().clone(),
        )),
        DNS_STRATEGY_TIMEOUT,
    )]);

    if should_accept_connection {
        deps.transport_connector
            .set_behaviors(allow_all_routes(&chat_domain_config, deps.static_ip_map()));
    }

    tokio::spawn(connect_websockets_on_incoming(incoming_streams));
    let (elapsed, outcome) = timed(deps.connect_chat().map_ok(|_| ())).await;

    assert_eq!(elapsed, expected_duration);
    if should_accept_connection {
        outcome.expect("accepted")
    } else {
        assert_matches!(outcome, Err(chat::ConnectError::AllAttemptsFailed));
    }
}
