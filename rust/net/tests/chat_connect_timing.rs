//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;

use assert_matches::assert_matches;
use async_trait::async_trait;
use libsignal_net::chat::ChatServiceError;
use libsignal_net::env::STAGING;
use libsignal_net::infra::errors::TransportConnectError;
use libsignal_net_infra::dns::dns_lookup::{DnsLookup, DnsLookupRequest};
use libsignal_net_infra::dns::{self, DnsResolver};
use test_case::test_case;
use tokio::time::{Duration, Instant};

mod fake_transport;
use fake_transport::{
    allow_proxy_hosts, connect_websockets_on_incoming, error_all_hosts_after, Behavior, FakeDeps,
};

/// Utility function to track how long a future takes to execute.
async fn timed<T>(f: impl Future<Output = T>) -> (Duration, T) {
    let time_at_first_poll = Instant::now();
    let t = f.await;
    let finished_at = Instant::now();
    (finished_at - time_at_first_poll, t)
}

trait ConnectChat {
    async fn start_connect(&self, deps: &FakeDeps) -> Result<(), ChatServiceError>;
}

struct ChatService;
impl ConnectChat for ChatService {
    async fn start_connect(&self, deps: &FakeDeps) -> Result<(), ChatServiceError> {
        deps.make_chat_service().connect_unauthenticated().await?;
        Ok(())
    }
}

struct ChatConnection;
impl ConnectChat for ChatConnection {
    async fn start_connect(&self, deps: &FakeDeps) -> Result<(), ChatServiceError> {
        deps.connect_chat().await?;
        Ok(())
    }
}

#[test_case(ChatService, Duration::from_secs(180))]
#[test_case(ChatConnection, Duration::from_secs(60))]
#[test_log::test(tokio::test(start_paused = true))]
async fn all_routes_connect_hangs_forever(connect: impl ConnectChat, expected_duration: Duration) {
    let (deps, _incoming_streams) = FakeDeps::new(&STAGING.chat_domain_config);

    let connect_chat = connect.start_connect(&deps);

    let (elapsed, outcome) = timed(connect_chat).await;

    assert_eq!(elapsed, expected_duration);
    assert_matches!(
        outcome,
        Err(ChatServiceError::TimeoutEstablishingConnection { attempts: 1 })
    );
}

#[test_case(ChatService, Duration::from_secs(120))]
#[test_case(ChatConnection, Duration::from_millis(500))]
#[test_log::test(tokio::test(start_paused = true))]
async fn only_proxies_are_reachable(connect: impl ConnectChat, expected_duration: Duration) {
    let (deps, incoming_streams) = FakeDeps::new(&STAGING.chat_domain_config);
    deps.transport_connector
        .set_behaviors(allow_proxy_hosts(&STAGING.chat_domain_config));
    let connect_chat = connect.start_connect(&deps);

    tokio::spawn(connect_websockets_on_incoming(incoming_streams));
    let (elapsed, outcome) = timed(connect_chat).await;

    assert_eq!(elapsed, expected_duration);
    assert_matches!(outcome, Ok(_));
}

#[test_case(ChatService, Duration::from_secs(60))]
#[test_case(ChatConnection, Duration::from_millis(500))]
#[test_log::test(tokio::test(start_paused = true))]
async fn direct_connect_fails_after_30s_but_proxies_reachable(
    connect: impl ConnectChat,
    expected_duration: Duration,
) {
    let (deps, incoming_streams) = FakeDeps::new(&STAGING.chat_domain_config);
    deps.transport_connector.set_behaviors(
        error_all_hosts_after(&STAGING.chat_domain_config, Duration::from_secs(30), || {
            TransportConnectError::TcpConnectionFailed
        })
        .chain(allow_proxy_hosts(&STAGING.chat_domain_config)),
    );
    let connect_chat = connect.start_connect(&deps);

    tokio::spawn(connect_websockets_on_incoming(incoming_streams));
    let (elapsed, outcome) = timed(connect_chat).await;

    assert_eq!(elapsed, expected_duration);
    assert_matches!(outcome, Ok(_));
}

#[test_case(ChatService, Duration::from_secs(180))]
#[test_case(ChatConnection, Duration::from_secs(60))]
#[test_log::test(tokio::test(start_paused = true))]

async fn transport_connects_but_websocket_never_responds(
    connect: impl ConnectChat,
    expected_duration: Duration,
) {
    let chat_domain_config = STAGING.chat_domain_config;
    let (deps, incoming_streams) = FakeDeps::new(&chat_domain_config);
    deps.transport_connector.set_behaviors([(
        chat_domain_config.connect.direct_connection_params().into(),
        Behavior::ReturnStream(vec![]),
    )]);
    let connect_chat = connect.start_connect(&deps);

    // Don't do anything with the incoming transport streams, just let them
    // accumulate in the unbounded stream.
    let _ignore_incoming_streams = incoming_streams;

    let (elapsed, outcome) = timed(connect_chat).await;

    assert_eq!(elapsed, expected_duration);
    assert_matches!(
        outcome,
        Err(ChatServiceError::TimeoutEstablishingConnection { attempts: 1 })
    );
}

#[test_case(ChatService, Duration::from_secs(120), Duration::ZERO)]
#[test_case(ChatConnection, Duration::from_millis(500), Duration::from_millis(500))]
#[test_log::test(tokio::test(start_paused = true))]
async fn connect_again_skips_timed_out_routes(
    connect: impl ConnectChat,
    expected_first_duration: Duration,
    expected_second_duration: Duration,
) {
    let (deps, incoming_streams) = FakeDeps::new(&STAGING.chat_domain_config);

    // For this test, only the proxy targets are reachable. The connection
    // manager should "learn" from the first attempt, after which a later
    // attempt will skip those routes and connect quickly.
    deps.transport_connector
        .set_behaviors(allow_proxy_hosts(&STAGING.chat_domain_config));
    tokio::spawn(connect_websockets_on_incoming(incoming_streams));

    {
        let connect_chat = connect.start_connect(&deps);

        let (elapsed, outcome) = timed(connect_chat).await;
        assert_matches!(outcome, Ok(_));
        assert_eq!(elapsed, expected_first_duration);
    }
    {
        let connect_chat = connect.start_connect(&deps);

        let (elapsed, outcome) = timed(connect_chat).await;
        assert_matches!(outcome, Ok(_));
        assert_eq!(elapsed, expected_second_duration);
    }
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
struct DnsLookupThatRunsSlowly(Duration);
#[async_trait]
impl DnsLookup for DnsLookupThatRunsSlowly {
    async fn dns_lookup(
        &self,
        request: DnsLookupRequest,
    ) -> dns::Result<dns::lookup_result::LookupResult> {
        tokio::time::sleep(self.0).await;
        FakeDeps::static_ip_map()
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

    deps.transport_connector.set_behaviors([(
        chat_domain_config.connect.direct_connection_params().into(),
        Behavior::Unreachable,
    )]);
    let connect_chat = ChatConnection.start_connect(&deps);

    // Don't do anything with the incoming transport streams, just let them
    // accumulate in the unbounded stream.
    let _ignore_incoming_streams = incoming_streams;

    let (elapsed, outcome) = timed(connect_chat).await;

    assert_eq!(elapsed, expected_duration);
    assert_matches!(
        outcome,
        Err(ChatServiceError::AllConnectionRoutesFailed { attempts: 1 })
    );
}

#[test_case(false, Duration::from_secs(60))]
#[test_case(true, Duration::from_secs(3))]
#[test_log::test(tokio::test(start_paused = true))]
async fn slow_dns(should_accept_connection: bool, expected_duration: Duration) {
    let chat_domain_config = STAGING.chat_domain_config;
    let (mut deps, incoming_streams) = FakeDeps::new(&chat_domain_config);
    deps.dns_resolver = DnsResolver::new_custom(vec![(
        Box::new(DnsLookupThatRunsSlowly(Duration::from_secs(3))),
        DNS_STRATEGY_TIMEOUT,
    )]);

    if should_accept_connection {
        deps.transport_connector.set_behaviors([(
            chat_domain_config.connect.direct_connection_params().into(),
            Behavior::ReturnStream(vec![]),
        )]);
    }

    let connect_chat = ChatConnection.start_connect(&deps);
    tokio::spawn(connect_websockets_on_incoming(incoming_streams));
    let (elapsed, outcome) = timed(connect_chat).await;

    assert_eq!(elapsed, expected_duration);
    if should_accept_connection {
        outcome.expect("accepted")
    } else {
        assert_matches!(
            outcome,
            Err(ChatServiceError::TimeoutEstablishingConnection { attempts: 1 })
        );
    }
}
