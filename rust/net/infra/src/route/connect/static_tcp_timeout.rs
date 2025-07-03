//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::future::Future;

use derive_where::derive_where;
use tokio::time::Duration;

use crate::errors::TransportConnectError;
use crate::route::Connector;

/// A [`Connector`] that enforces a timeout on TCP connections.
///
/// This connector wraps another connector and ensures that connection attempts
/// time out after the specified duration. If the inner connector succeeds
/// or fails before the timeout, the result is returned immediately. If the timeout
/// is reached before the connection completes, it returns `TcpConnectionFailed`.
///
/// This is necessary because we've seen some cases where TCP connections
/// hang indefinitely, especially on Android phones, where the OS puts us
/// in a network blackhole going in and out of the background.
#[derive_where(Debug; Inner: Debug)]
pub struct StaticTcpTimeoutConnector<Inner> {
    inner_connector: Inner,
    timeout: Duration,
}

impl<I> StaticTcpTimeoutConnector<I> {
    pub fn new(inner: I, timeout: Duration) -> Self {
        Self {
            inner_connector: inner,
            timeout,
        }
    }

    /// Consumes the connector and returns its inner connector and timeout.
    pub fn into_connector_and_timeout(self) -> (I, Duration) {
        (self.inner_connector, self.timeout)
    }
}

impl<I: Default> Default for StaticTcpTimeoutConnector<I> {
    fn default() -> Self {
        Self {
            inner_connector: I::default(),
            timeout: crate::timeouts::TCP_CONNECTION_TIMEOUT,
        }
    }
}

impl<Inner, Route, Transport> Connector<Route, Transport> for StaticTcpTimeoutConnector<Inner>
where
    Inner: Connector<Route, Transport, Error = TransportConnectError> + Sync,
    Inner::Connection: Send,
    Route: Send,
    Transport: Send,
{
    type Connection = Inner::Connection;

    type Error = TransportConnectError;

    fn connect_over(
        &self,
        transport: Transport,
        route: Route,
        log_tag: &str,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let Self {
            inner_connector,
            timeout,
        } = self;

        async move {
            tokio::time::timeout(
                *timeout,
                inner_connector.connect_over(transport, route, log_tag),
            )
            .await
            .map_err(|_| TransportConnectError::TcpConnectionFailed)?
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::route::connect::testutils::{DummyConnection, DummyDelayConnector};

    const TEST_TRANSPORT: () = ();
    const TEST_ROUTE: () = ();
    const LOG_TAG: &str = "test";

    struct FailingConnector;

    impl<R, T> Connector<R, T> for FailingConnector
    where
        R: Send,
        T: Send,
    {
        type Connection = DummyConnection;
        type Error = TransportConnectError;

        async fn connect_over(
            &self,
            _transport: T,
            _route: R,
            _log_tag: &str,
        ) -> Result<Self::Connection, Self::Error> {
            Err(TransportConnectError::TcpConnectionFailed)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_success_returns_immediately() {
        let inner_delay = Duration::from_millis(100);
        let timeout = Duration::from_secs(5);

        let inner = DummyDelayConnector { delay: inner_delay };
        let connector = StaticTcpTimeoutConnector::new(inner, timeout);

        let start = tokio::time::Instant::now();
        let result: Result<DummyConnection, _> = connector
            .connect_over(TEST_TRANSPORT, TEST_ROUTE, LOG_TAG)
            .await;

        assert_matches!(result, Ok(_), "Expected successful connection");
        let elapsed = start.elapsed();
        assert_eq!(elapsed, inner_delay);
    }

    #[tokio::test(start_paused = true)]
    async fn test_failure_returns_immediately() {
        let timeout = Duration::from_secs(5);

        let inner = FailingConnector;
        let connector = StaticTcpTimeoutConnector::new(inner, timeout);

        let start = tokio::time::Instant::now();
        let result: Result<DummyConnection, _> = connector
            .connect_over(TEST_TRANSPORT, TEST_ROUTE, LOG_TAG)
            .await;

        assert_matches!(
            result,
            Err(TransportConnectError::TcpConnectionFailed),
            "Expected connection failure"
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed < timeout,
            "Failed connection should return immediately, but took {:?}",
            elapsed
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_timeout_returns_tcp_connection_failed() {
        let inner_delay = Duration::from_secs(10);
        let timeout = Duration::from_secs(5);

        let inner = DummyDelayConnector { delay: inner_delay };
        let connector = StaticTcpTimeoutConnector::new(inner, timeout);

        let start = tokio::time::Instant::now();
        let result: Result<DummyConnection, _> = connector
            .connect_over(TEST_TRANSPORT, TEST_ROUTE, LOG_TAG)
            .await;

        assert_matches!(
            result,
            Err(TransportConnectError::TcpConnectionFailed),
            "Expected timeout error"
        );
        let elapsed = start.elapsed();
        assert_eq!(
            elapsed, timeout,
            "Timeout should occur after {:?}, but took {:?}",
            timeout, elapsed
        );
    }
}
