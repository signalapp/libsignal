//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cmp::{max, min};
use std::fmt::Debug;
use std::future::Future;
use std::ops::Add;
use std::panic::RefUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::time::{timeout_at, Instant};

use crate::infra::errors::LogSafeDisplay;
use crate::infra::ConnectionParams;

pub(crate) const MAX_COOLDOWN_INTERVAL: Duration = Duration::from_secs(64);

const COOLDOWN_INTERVALS: [Duration; 8] = [
    Duration::from_secs(0),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(32),
    MAX_COOLDOWN_INTERVAL,
];

/// Represents the outcome of the connection attempt
#[derive(Debug)]
pub enum ConnectionAttemptOutcome<T, E> {
    /// Connection was attempted and the result is held by this variant.
    Attempted(Result<T, E>),
    /// Connection was attempted and timed out.
    /// This means that we don't have a connection-specific error to report,
    /// so the `Attempted` variant can't be used.
    TimedOut,
    /// Connection was not attempted because connection manager is in a cooldown state.
    /// Next attempt will happen no earlier than the `Instant` held by this variant.
    WaitUntil(Instant),
}

/// Encapsulates the logic that for every connection attempt decides
/// whether or not an attempt is to be made in the first place, and, if yes,
/// which [ConnectionParams] are to be used for the attempt.
#[async_trait]
pub trait ConnectionManager: Clone + Send + Sync {
    async fn connect_or_wait<'a, T, E, Fun, Fut>(
        &'a self,
        connection_fn: Fun,
    ) -> ConnectionAttemptOutcome<T, E>
    where
        T: Send,
        E: Send + Debug + LogSafeDisplay,
        Fun: Fn(&'a ConnectionParams) -> Fut + Send + Sync,
        Fut: Future<Output = Result<T, E>> + Send;
}

#[async_trait]
impl<C> ConnectionManager for &'_ C
where
    C: ConnectionManager,
{
    async fn connect_or_wait<'a, T, E, Fun, Fut>(
        &'a self,
        connection_fn: Fun,
    ) -> ConnectionAttemptOutcome<T, E>
    where
        T: Send,
        E: Send + Debug + LogSafeDisplay,
        Fun: Fn(&'a ConnectionParams) -> Fut + Send + Sync,
        Fut: Future<Output = Result<T, E>> + Send,
    {
        (*self).connect_or_wait(connection_fn).await
    }
}

#[derive(Clone, Debug)]
struct ThrottlingConnectionManagerState {
    consecutive_fails: u16,
    next_attempt: Instant,
    latest_attempt: Instant,
}

impl ThrottlingConnectionManagerState {
    /// Produces a new state after a success or failure.
    ///
    /// The logic here is to track an attempt start time and to take it into
    /// account when updating the state. Then, if we see failed attempts that
    /// started before some successful attempt, those failed attempts are
    /// discarded. If, however, outcomes of failed attempts are arriving out of
    /// order in which attempts started, those failures will still be reflected
    /// in `consecutive_fails`.
    fn after_attempt(self, was_successful: bool, attempt_start_time: Instant) -> Self {
        let mut s = self;
        if was_successful {
            // comparing using `>=` to guarantee that successful attempt takes precedence
            if attempt_start_time >= s.latest_attempt {
                s.latest_attempt = attempt_start_time;
                s.consecutive_fails = 0;
                s.next_attempt = attempt_start_time;
            }
        } else if attempt_start_time > s.latest_attempt || s.consecutive_fails > 0 {
            s.latest_attempt = max(attempt_start_time, s.latest_attempt);
            let idx: usize = s.consecutive_fails.into();
            let cooldown_interval = COOLDOWN_INTERVALS
                .get(idx)
                .unwrap_or(&MAX_COOLDOWN_INTERVAL);
            s.next_attempt = Instant::now() + *cooldown_interval;
            s.consecutive_fails = min(
                s.consecutive_fails.saturating_add(1),
                (COOLDOWN_INTERVALS.len() - 1).try_into().unwrap(),
            );
        }
        s
    }
}

/// A connection manager that only attempts one route (i.e. one [ConnectionParams])
/// but keeps track of consecutive failed attempts and after each failure waits for a duration
/// chosen according to [COOLDOWN_INTERVALS] list.
#[derive(Clone)]
pub struct SingleRouteThrottlingConnectionManager {
    state: Arc<Mutex<ThrottlingConnectionManagerState>>,
    connection_params: ConnectionParams,
    connection_timeout: Duration,
}

/// A connection manager that holds a list of [SingleRouteThrottlingConnectionManager] instances
/// and iterates over them until it can find one that results in a successful connection attempt.
/// If none did, it will return [ConnectionAttemptOutcome::WaitUntil] with the minimum possible
/// cooldown time (based on cooldown times returned by all throttling connection managers).
#[derive(Clone)]
pub struct MultiRouteConnectionManager<M = SingleRouteThrottlingConnectionManager> {
    route_managers: Vec<M>,
    connection_timeout: Duration,
}

impl<M> MultiRouteConnectionManager<M> {
    pub fn new(route_managers: Vec<M>, connection_timeout: Duration) -> Self {
        Self {
            route_managers,
            connection_timeout,
        }
    }
}

#[async_trait]
impl<M> ConnectionManager for MultiRouteConnectionManager<M>
where
    M: ConnectionManager,
{
    /// Tries to establish a connection using one of the configured options.
    ///
    /// In the case of the `MultiRouteConnectionManager`, we have a list of options
    /// in the order of preference. The idea is to try those options one after another
    /// in the given order. If some option is permanently unavailable due to some external
    /// limitations it will soon reach the "cooldown" state and no time will be wasted
    /// on trying it. As a result, it's unlikely that we will be waiting on more than one
    /// connection attempt, except maybe the case of the few first requests.
    async fn connect_or_wait<'a, T, E, Fun, Fut>(
        &'a self,
        connection_fn: Fun,
    ) -> ConnectionAttemptOutcome<T, E>
    where
        T: Send,
        E: Send + Debug + LogSafeDisplay,
        Fun: Fn(&'a ConnectionParams) -> Fut + Send + Sync,
        Fut: Future<Output = Result<T, E>> + Send,
    {
        let now = Instant::now();
        let deadline = now + self.connection_timeout;
        let mut earliest_retry = now + MAX_COOLDOWN_INTERVAL;
        for route_manager in self.route_managers.iter() {
            loop {
                let result_or_timeout =
                    timeout_at(deadline, route_manager.connect_or_wait(&connection_fn)).await;
                let result = match result_or_timeout {
                    Ok(r) => r,
                    Err(_) => return ConnectionAttemptOutcome::TimedOut,
                };
                match result {
                    ConnectionAttemptOutcome::Attempted(Ok(r)) => {
                        return ConnectionAttemptOutcome::Attempted(Ok(r));
                    }
                    ConnectionAttemptOutcome::Attempted(Err(e)) => {
                        log::debug!("Connection attempt failed with an error: {:?}", e);
                        log::info!("Connection attempt failed with an error: {}", e);
                        continue;
                    }
                    ConnectionAttemptOutcome::TimedOut => {
                        log::info!("Connection attempt timed out");
                        continue;
                    }
                    ConnectionAttemptOutcome::WaitUntil(i) => {
                        if i < earliest_retry {
                            earliest_retry = i
                        }
                        break;
                    }
                }
            }
        }
        ConnectionAttemptOutcome::WaitUntil(earliest_retry)
    }
}

impl SingleRouteThrottlingConnectionManager {
    pub fn new(connection_params: ConnectionParams, connection_timeout: Duration) -> Self {
        Self {
            connection_params,
            connection_timeout,
            state: Arc::new(Mutex::new(ThrottlingConnectionManagerState {
                consecutive_fails: 0,
                next_attempt: Instant::now(),
                latest_attempt: Instant::now(),
            })),
        }
    }
}

/// Declare &SingleRouteThrottlingConnectionManager unwind-safe.
///
/// This is guaranteed by the impl blocks, which only update locked state
/// atomically to avoid logic errors.
impl RefUnwindSafe for SingleRouteThrottlingConnectionManager {}

#[async_trait]
impl ConnectionManager for SingleRouteThrottlingConnectionManager {
    async fn connect_or_wait<'a, T, E, Fun, Fut>(
        &'a self,
        connection_fn: Fun,
    ) -> ConnectionAttemptOutcome<T, E>
    where
        T: Send,
        E: Send,
        Fun: Fn(&'a ConnectionParams) -> Fut + Send + Sync,
        Fut: Future<Output = Result<T, E>> + Send,
    {
        let state = self.state.lock().await.clone();
        let attempt_start_time = Instant::now();
        if attempt_start_time < state.next_attempt {
            return ConnectionAttemptOutcome::WaitUntil(state.next_attempt);
        }
        let connection_result_or_timeout = timeout_at(
            attempt_start_time.add(self.connection_timeout),
            connection_fn(&self.connection_params),
        )
        .await;

        let mut s = self.state.lock().await;

        // Ensure unwind safety by atomically updating the locked state with
        // respect to panics.
        let was_successful = connection_result_or_timeout
            .as_ref()
            .map_or(false, |r| r.is_ok());
        let new_state = s.clone().after_attempt(was_successful, attempt_start_time);
        *s = new_state;

        connection_result_or_timeout.map_or(ConnectionAttemptOutcome::TimedOut, |result| {
            ConnectionAttemptOutcome::Attempted(result)
        })
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Borrow;
    use std::future;

    use assert_matches::assert_matches;
    use tokio::time;

    use crate::infra::certs::RootCertificates;
    use crate::infra::dns::DnsResolver;
    use crate::infra::test::shared::{
        TestError, FEW_ATTEMPTS, LONG_CONNECTION_TIME, MANY_ATTEMPTS, TIMEOUT_DURATION,
        TIME_ADVANCE_VALUE,
    };
    use crate::infra::HttpRequestDecoratorSeq;

    use super::*;

    const ROUTE_THAT_TIMES_OUT: &str = "timeout.signal.org";

    const ROUTE_1: &str = "route1.signal.org";

    const ROUTE_2: &str = "route2.signal.org";

    #[tokio::test]
    async fn single_route_successfull_attempts() {
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params("chat.staging.signal.org"),
            TIMEOUT_DURATION,
        );
        for _ in 0..FEW_ATTEMPTS {
            let attempt_outcome: ConnectionAttemptOutcome<(), TestError> =
                manager.connect_or_wait(|_| future::ready(Ok(()))).await;
            assert_matches!(attempt_outcome, ConnectionAttemptOutcome::Attempted(Ok(())));
        }
    }

    #[tokio::test]
    async fn single_route_alternating() {
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params("chat.staging.signal.org"),
            TIMEOUT_DURATION,
        );
        for _ in 0..FEW_ATTEMPTS {
            let attempt_outcome: ConnectionAttemptOutcome<(), TestError> = manager
                .connect_or_wait(|_| future::ready(Err(TestError::Expected)))
                .await;
            assert_matches!(
                attempt_outcome,
                ConnectionAttemptOutcome::Attempted(Err(TestError::Expected))
            );
            let attempt_outcome: ConnectionAttemptOutcome<(), TestError> =
                manager.connect_or_wait(|_| future::ready(Ok(()))).await;
            assert_matches!(attempt_outcome, ConnectionAttemptOutcome::Attempted(Ok(())));
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn single_route_manager_times_out_on_long_connection() {
        let time_over_timeout = TIMEOUT_DURATION * 2;
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params("chat.staging.signal.org"),
            TIMEOUT_DURATION,
        );
        time::advance(TIME_ADVANCE_VALUE).await;
        // first attempt
        let attempt_outcome: ConnectionAttemptOutcome<(), TestError> = manager
            .connect_or_wait(|_| async {
                tokio::time::sleep(time_over_timeout).await;
                future::ready(Err(TestError::Expected)).await
            })
            .await;
        assert_matches!(attempt_outcome, ConnectionAttemptOutcome::TimedOut);

        // second attempt
        let attempt_outcome: ConnectionAttemptOutcome<(), TestError> = manager
            .connect_or_wait(|_| async {
                tokio::time::sleep(time_over_timeout).await;
                future::ready(Err(TestError::Expected)).await
            })
            .await;
        assert_matches!(attempt_outcome, ConnectionAttemptOutcome::TimedOut);

        // third attempt: cooling down
        let attempt_outcome: ConnectionAttemptOutcome<(), TestError> = manager
            .connect_or_wait(|_| async {
                tokio::time::sleep(time_over_timeout).await;
                future::ready(Err(TestError::Expected)).await
            })
            .await;
        assert_matches!(attempt_outcome, ConnectionAttemptOutcome::WaitUntil(_));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn single_route_manager_handles_too_many_failed_attempts() {
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params("chat.staging.signal.org"),
            TIMEOUT_DURATION,
        );
        for _ in 0..MANY_ATTEMPTS {
            time::advance(TIME_ADVANCE_VALUE).await;
            let _attempt_outcome: ConnectionAttemptOutcome<(), TestError> = manager
                .connect_or_wait(|_| future::ready(Err(TestError::Expected)))
                .await;
        }
        // now checking to see if we're in `Cooldown`
        let attempt_outcome: ConnectionAttemptOutcome<(), TestError> = manager
            .connect_or_wait(|_| future::ready(Err(TestError::Expected)))
            .await;
        assert_matches!(attempt_outcome, ConnectionAttemptOutcome::WaitUntil(_));

        // now let's advance the time to the point after the cooldown period
        time::advance(MAX_COOLDOWN_INTERVAL).await;
        let attempt_outcome: ConnectionAttemptOutcome<(), TestError> =
            manager.connect_or_wait(|_| future::ready(Ok(()))).await;
        assert_matches!(attempt_outcome, ConnectionAttemptOutcome::Attempted(Ok(())));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn multi_route_manager_picks_working_route() {
        let manager_1 = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(ROUTE_1),
            TIMEOUT_DURATION,
        );
        let manager_2 = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(ROUTE_2),
            TIMEOUT_DURATION,
        );
        let multi_route_manager =
            MultiRouteConnectionManager::new(vec![manager_1, manager_2], Duration::from_secs(2));

        // route1 is working
        time::advance(TIME_ADVANCE_VALUE).await;
        validate_expected_route(&multi_route_manager, true, ROUTE_1).await;
        // now route1 stopped working
        for _ in 0..3 {
            time::advance(TIME_ADVANCE_VALUE).await;
            validate_expected_route(&multi_route_manager, false, ROUTE_2).await;
        }
        // route1 is working again, but it's in cooldown, so we are still expecting route2
        time::advance(TIME_ADVANCE_VALUE).await;
        validate_expected_route(&multi_route_manager, true, ROUTE_2).await;

        // and now after a cooldown period, route1 should be used again
        time::advance(MAX_COOLDOWN_INTERVAL).await;
        validate_expected_route(&multi_route_manager, true, ROUTE_1).await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn multi_route_manager_picks_working_route_after_timed_out_route() {
        let timing_out_route_manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(ROUTE_THAT_TIMES_OUT),
            TIMEOUT_DURATION,
        );
        let manager_1 = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(ROUTE_1),
            TIMEOUT_DURATION,
        );
        let multi_route_manager = MultiRouteConnectionManager::new(
            vec![timing_out_route_manager, manager_1],
            TIMEOUT_DURATION * 2,
        );

        time::advance(TIME_ADVANCE_VALUE).await;
        validate_expected_route(&multi_route_manager, true, ROUTE_1).await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn multi_route_manager_times_out() {
        let timing_out_route_manager_1 = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(ROUTE_THAT_TIMES_OUT),
            TIMEOUT_DURATION,
        );
        let timing_out_route_manager_2 = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(ROUTE_THAT_TIMES_OUT),
            TIMEOUT_DURATION,
        );
        let multi_route_manager = MultiRouteConnectionManager::new(
            vec![timing_out_route_manager_1, timing_out_route_manager_2],
            TIMEOUT_DURATION * 2,
        );

        time::advance(TIME_ADVANCE_VALUE).await;
        let attempt_outcome: ConnectionAttemptOutcome<&str, TestError> = multi_route_manager
            .connect_or_wait(|connection_params| simulate_connect(connection_params, true))
            .await;
        assert_matches!(attempt_outcome, ConnectionAttemptOutcome::TimedOut);
    }

    async fn validate_expected_route(
        multi_route_manager: &MultiRouteConnectionManager,
        route1_healthy: bool,
        expected_route: &str,
    ) {
        let attempt_outcome: ConnectionAttemptOutcome<&str, TestError> = multi_route_manager
            .connect_or_wait(|connection_params| async move {
                simulate_connect(connection_params, route1_healthy).await
            })
            .await;
        assert_matches!(
            attempt_outcome,
            ConnectionAttemptOutcome::Attempted(Ok(a)) if a == expected_route
        );
    }

    async fn simulate_connect(
        connection_params: &ConnectionParams,
        route1_healthy: bool,
    ) -> Result<&str, TestError> {
        let route1_response = match route1_healthy {
            true => Ok(ROUTE_1),
            false => Err(TestError::Expected),
        };
        match connection_params.host.borrow() {
            ROUTE_1 => future::ready(route1_response).await,
            ROUTE_2 => future::ready(Ok(ROUTE_2)).await,
            ROUTE_THAT_TIMES_OUT => {
                tokio::time::sleep(LONG_CONNECTION_TIME).await;
                future::ready(Ok(ROUTE_THAT_TIMES_OUT)).await
            }
            _ => future::ready(Err(TestError::Unexpected("not configured for the route"))).await,
        }
    }

    fn example_connection_params(host: &str) -> ConnectionParams {
        ConnectionParams::new(
            host,
            host,
            443,
            HttpRequestDecoratorSeq::default(),
            RootCertificates::Signal,
            DnsResolver::System,
        )
    }
}
