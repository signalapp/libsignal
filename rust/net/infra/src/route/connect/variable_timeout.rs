//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;

use derive_where::derive_where;
use tokio::time::Duration;

use crate::errors::TlsHandshakeTimeout;
use crate::route::Connector;

/// A [`Connector`] that applies a variable timeout based on inner connection time
/// to an outer connector.
///
/// This connector is similar to `ComposedConnector` but specifically focused on the
/// variable timeout behavior. It times how long the inner connection takes and applies
/// a timeout to the outer connection based on that time.
#[derive_where(Debug; Outer: Debug, Inner: Debug)]
pub struct VariableTlsTimeoutConnector<Outer, Inner, Error> {
    outer_connector: Outer,
    inner_connector: Inner,
    min_timeout: Duration,
    /// The type of error returned by [`Connector::connect_over`].
    ///
    /// This lets us produce an error type that is distinct from the inner and
    /// outer `Connector` error types.
    _error: PhantomData<Error>,
}

impl<O, I, E> VariableTlsTimeoutConnector<O, I, E> {
    pub fn new(outer: O, inner: I, min_timeout: Duration) -> Self {
        Self {
            outer_connector: outer,
            inner_connector: inner,
            min_timeout,
            _error: PhantomData,
        }
    }

    /// Consumes the connector and returns its constituents and min_timeout.
    pub fn into_connectors_and_min_timeout(self) -> (O, I, Duration) {
        (self.outer_connector, self.inner_connector, self.min_timeout)
    }

    pub fn connect_inner_then_outer_with_timeout<'a, IR: Send, OR: Send, S: Send>(
        &self,
        transport: S,
        inner_route: IR,
        outer_route: OR,
        log_tag: &'a str,
    ) -> impl Future<Output = Result<O::Connection, E>> + Send + use<'_, 'a, IR, OR, S, O, I, E>
    where
        O: Connector<OR, I::Connection, Error: Into<E>> + Sync,
        I: Connector<IR, S, Error: Into<E>> + Sync,
        E: From<TlsHandshakeTimeout>,
    {
        let Self {
            inner_connector,
            outer_connector,
            min_timeout,
            _error,
        } = self;
        async move {
            let start = tokio::time::Instant::now();
            let inner_connected = inner_connector
                .connect_over(transport, inner_route, log_tag)
                .await
                .map_err(Into::into)?;

            let estimated_tcp_rtt = start.elapsed();
            // In worst case, TLS can take two round-trips, if the server rejects our first client secret share.
            // Plus, we might need re-transmits if there is packet loss.
            // So, we use a timeout of five times the estimated TCP RTT, to include enough time for two round-trips
            //   and re-transmits.
            let timeout = std::cmp::max(*min_timeout, estimated_tcp_rtt * 5);
            tokio::time::timeout(
                timeout,
                outer_connector.connect_over(inner_connected, outer_route, log_tag),
            )
            .await
            .map_err(|_| TlsHandshakeTimeout)?
            .map_err(Into::into)
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::errors::{FailedHandshakeReason, TransportConnectError};
    use crate::route::connect::testutils::{DummyConnection, DummyDelayConnector};

    const TEST_TRANSPORT: () = ();
    const TEST_ROUTE: () = ();
    const LOG_TAG: &str = "test";

    #[tokio::test(start_paused = true)]
    async fn test_success() {
        let inner_delay = Duration::from_millis(300);
        let outer_delay = Duration::from_millis(500);
        let min_timeout = Duration::from_millis(100);

        let inner = DummyDelayConnector { delay: inner_delay };
        let outer = DummyDelayConnector { delay: outer_delay };
        let connector: VariableTlsTimeoutConnector<_, _, TransportConnectError> =
            VariableTlsTimeoutConnector::new(outer, inner, min_timeout);

        let result: Result<DummyConnection, _> = connector
            .connect_inner_then_outer_with_timeout(TEST_TRANSPORT, TEST_ROUTE, TEST_ROUTE, LOG_TAG)
            .await;
        assert_matches!(result, Ok(_), "Expected successful connection");
    }

    #[tokio::test(start_paused = true)]
    async fn test_min_timeout_failure() {
        let inner_delay = Duration::from_millis(1);
        let outer_delay = Duration::from_millis(1001);
        let min_timeout = Duration::from_millis(1000);

        let inner = DummyDelayConnector { delay: inner_delay };
        let outer = DummyDelayConnector { delay: outer_delay };
        let connector: VariableTlsTimeoutConnector<_, _, TransportConnectError> =
            VariableTlsTimeoutConnector::new(outer, inner, min_timeout);

        let result = connector
            .connect_inner_then_outer_with_timeout(TEST_TRANSPORT, TEST_ROUTE, TEST_ROUTE, LOG_TAG)
            .await;

        let reason = assert_matches!(result, Err(TransportConnectError::SslFailedHandshake(reason)) => reason);
        assert_eq!(
            reason,
            FailedHandshakeReason::TIMED_OUT,
            "Expected timeout error"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_variable_timeout_failure() {
        let inner_delay = Duration::from_millis(300);
        let outer_delay = Duration::from_millis(1600);
        let min_timeout = Duration::from_millis(100);

        let inner = DummyDelayConnector { delay: inner_delay };
        let outer = DummyDelayConnector { delay: outer_delay };
        let connector: VariableTlsTimeoutConnector<_, _, TransportConnectError> =
            VariableTlsTimeoutConnector::new(outer, inner, min_timeout);

        let result = connector
            .connect_inner_then_outer_with_timeout(TEST_TRANSPORT, TEST_ROUTE, TEST_ROUTE, LOG_TAG)
            .await;

        let reason = assert_matches!(result, Err(TransportConnectError::SslFailedHandshake(reason)) => reason);
        assert_eq!(
            reason,
            FailedHandshakeReason::TIMED_OUT,
            "Expected timeout error"
        );
    }
}
