//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::Duration;

use crate::errors::LogSafeDisplay;
use crate::route::Connector;

/// A [`Connector`] that logs when a connection attempt exceeds a predefined timeout threshold.
///
/// Unlike other timeout wrappers, this connector doesn't abort the connection - it just logs that
/// the connection is taking longer than expected while allowing it to continue.
///
/// If multiple connections are made at the same time, it's recommended to give each one a custom
/// log tag so their logs don't get mixed up.
#[derive(Debug)]
pub struct LoggingConnector<Inner> {
    inner_connector: Inner,
    slow_connection_threshold: Duration,
    label: &'static str,
}

impl<I> LoggingConnector<I> {
    pub fn new(inner: I, slow_connection_threshold: Duration, label: &'static str) -> Self {
        Self {
            inner_connector: inner,
            slow_connection_threshold,
            label,
        }
    }

    pub fn into_inner(self) -> I {
        self.inner_connector
    }
}

impl<I, R, Inner> Connector<R, Inner> for LoggingConnector<I>
where
    I: Connector<R, Inner, Connection: Send, Error: Send + LogSafeDisplay> + Sync,
    R: Send,
    Inner: Send,
{
    type Connection = I::Connection;
    type Error = I::Error;

    async fn connect_over(
        &self,
        over: Inner,
        route: R,
        log_tag: &str,
    ) -> Result<Self::Connection, Self::Error> {
        let Self {
            inner_connector,
            slow_connection_threshold,
            label,
        } = self;

        let start = tokio::time::Instant::now();
        let threshold = *slow_connection_threshold;

        #[cfg(target_os = "android")]
        log::info!("[{log_tag}] {label} connection attempt started");

        let mut connect = std::pin::pin!(inner_connector.connect_over(over, route, log_tag));

        let result = match tokio::time::timeout(threshold, connect.as_mut()).await {
            Ok(result) => result,
            Err(_timeout) => {
                log::warn!("[{log_tag}] {label} is taking longer than expected (>{threshold:?})");
                connect.await
            }
        };

        // Log completion with timing information.
        let elapsed = start.elapsed();
        match &result {
            Ok(_) => {
                if elapsed > threshold {
                    log::info!(
                        "[{log_tag}] {label} succeeded after {elapsed:.3?} (exceeded threshold of {threshold:?})",
                    );
                } else {
                    log::debug!("[{log_tag}] {label} succeeded after {elapsed:.3?}");
                }
            }
            Err(e) => {
                if elapsed > threshold {
                    log::warn!(
                        "[{log_tag}] {label} failed after {elapsed:.3?} (exceeded threshold of {threshold:?}): {}",
                        e as &dyn LogSafeDisplay
                    );
                } else {
                    log::info!(
                        "[{log_tag}] {label} failed after {elapsed:.3?}: {}",
                        e as &dyn LogSafeDisplay
                    );
                }
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use assert_matches::assert_matches;

    use super::*;
    use crate::route::connect::testutils::DummyDelayConnector;

    const TEST_TRANSPORT: () = ();
    const TEST_ROUTE: () = ();
    const LOG_TAG: &str = "test";

    #[tokio::test(start_paused = true)]
    async fn test_fast_connection() {
        let inner_delay = Duration::from_millis(50);
        let threshold = Duration::from_millis(100);

        let inner = DummyDelayConnector { delay: inner_delay };
        let connector = LoggingConnector::new(inner, threshold, "test");

        let result = connector
            .connect_over(TEST_TRANSPORT, TEST_ROUTE, LOG_TAG)
            .await;
        assert_matches!(result, Ok(_), "Expected successful connection");
    }

    #[tokio::test(start_paused = true)]
    async fn test_slow_connection() {
        let inner_delay = Duration::from_millis(150);
        let threshold = Duration::from_millis(100);

        let inner = DummyDelayConnector { delay: inner_delay };
        let connector = LoggingConnector::new(inner, threshold, "test");

        let result = connector
            .connect_over(TEST_TRANSPORT, TEST_ROUTE, LOG_TAG)
            .await;
        assert_matches!(
            result,
            Ok(_),
            "Expected successful connection even though it was slow"
        );
    }
}
