//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;

use assert_matches::assert_matches;
use libsignal_net::chat::ChatServiceError;
use libsignal_net::env::STAGING;
use libsignal_net::infra::errors::TransportConnectError;
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

#[test_log::test(tokio::test(start_paused = true))]
async fn all_routes_connect_hangs_forever() {
    let (deps, _incoming_streams) = FakeDeps::new(&STAGING.chat_domain_config);
    let chat = deps.make_chat();

    let (elapsed, outcome) = timed(chat.connect_unauthenticated()).await;

    assert_eq!(elapsed, Duration::from_secs(180));
    assert_matches!(
        outcome,
        Err(ChatServiceError::TimeoutEstablishingConnection { attempts: 1 })
    );
}

#[test_log::test(tokio::test(start_paused = true))]
async fn only_proxies_are_reachable() {
    let (deps, incoming_streams) = FakeDeps::new(&STAGING.chat_domain_config);
    deps.transport_connector
        .set_behaviors(allow_proxy_hosts(&STAGING.chat_domain_config));
    let chat = deps.make_chat();

    tokio::spawn(connect_websockets_on_incoming(incoming_streams));
    let (elapsed, outcome) = timed(chat.connect_unauthenticated()).await;

    assert_eq!(elapsed, Duration::from_secs(120));
    assert_matches!(outcome, Ok(_));
}

#[test_log::test(tokio::test(start_paused = true))]
async fn direct_connect_fails_after_30s_but_proxies_reachable() {
    let (deps, incoming_streams) = FakeDeps::new(&STAGING.chat_domain_config);
    deps.transport_connector.set_behaviors(
        error_all_hosts_after(&STAGING.chat_domain_config, Duration::from_secs(30), || {
            TransportConnectError::TcpConnectionFailed
        })
        .chain(allow_proxy_hosts(&STAGING.chat_domain_config)),
    );
    let chat = deps.make_chat();

    tokio::spawn(connect_websockets_on_incoming(incoming_streams));
    let (elapsed, outcome) = timed(chat.connect_unauthenticated()).await;

    assert_eq!(elapsed, Duration::from_secs(60));
    assert_matches!(outcome, Ok(_));
}

#[test_log::test(tokio::test(start_paused = true))]
async fn transport_connects_but_websocket_never_responds() {
    let chat_domain_config = STAGING.chat_domain_config;
    let (deps, incoming_streams) = FakeDeps::new(&chat_domain_config);
    deps.transport_connector.set_behaviors([(
        chat_domain_config.connect.direct_connection_params().into(),
        Behavior::ReturnStream(vec![]),
    )]);
    let chat = deps.make_chat();

    // Don't do anything with the incoming transport streams, just let them
    // accumulate in the unbounded stream.
    let _ignore_incoming_streams = incoming_streams;

    let (elapsed, outcome) = timed(chat.connect_unauthenticated()).await;

    assert_eq!(elapsed, Duration::from_secs(180));
    assert_matches!(
        outcome,
        Err(ChatServiceError::TimeoutEstablishingConnection { attempts: 1 })
    );
}

#[test_log::test(tokio::test(start_paused = true))]
async fn connect_again_skips_timed_out_routes() {
    let (deps, incoming_streams) = FakeDeps::new(&STAGING.chat_domain_config);

    // For this test, only the proxy targets are reachable. The connection
    // manager should "learn" from the first attempt, after which a later
    // attempt will skip those routes and connect quickly.
    deps.transport_connector
        .set_behaviors(allow_proxy_hosts(&STAGING.chat_domain_config));
    tokio::spawn(connect_websockets_on_incoming(incoming_streams));

    {
        let chat = deps.make_chat();

        let (elapsed, outcome) = timed(chat.connect_unauthenticated()).await;
        assert_matches!(outcome, Ok(_));
        assert_eq!(elapsed, Duration::from_secs(120));
    }
    {
        let chat = deps.make_chat();

        let (elapsed, outcome) = timed(chat.connect_unauthenticated()).await;
        assert_matches!(outcome, Ok(_));
        assert_eq!(elapsed, Duration::ZERO);
    }
}
