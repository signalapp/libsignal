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

use crate::timeouts::{CONNECTION_ROUTE_COOLDOWN_INTERVALS, CONNECTION_ROUTE_MAX_COOLDOWN};
use async_trait::async_trait;
use itertools::Itertools;
use tokio::sync::Mutex;
use tokio::time::{timeout_at, Instant};

use crate::infra::errors::LogSafeDisplay;
use crate::infra::ConnectionParams;

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
/// whether an attempt is to be made in the first place, and, if yes,
/// which [ConnectionParams] are to be used for the attempt.
#[async_trait]
pub trait ConnectionManager: Clone + Send + Sync {
    async fn connect_or_wait<'a, T, E, Fun, Fut>(
        &'a self,
        connection_fn: Fun,
    ) -> ConnectionAttemptOutcome<T, E>
    where
        T: Send,
        E: Send + Debug + LogSafeDisplay + ErrorClassifier,
        Fun: Fn(&'a ConnectionParams) -> Fut + Send + Sync,
        Fut: Future<Output = Result<T, E>> + Send;

    fn describe_for_logging(&self) -> String;
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
        E: Send + Debug + LogSafeDisplay + ErrorClassifier,
        Fun: Fn(&'a ConnectionParams) -> Fut + Send + Sync,
        Fut: Future<Output = Result<T, E>> + Send,
    {
        (*self).connect_or_wait(connection_fn).await
    }

    fn describe_for_logging(&self) -> String {
        (*self).describe_for_logging()
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
            let cooldown_interval = CONNECTION_ROUTE_COOLDOWN_INTERVALS
                .get(idx)
                .unwrap_or(&CONNECTION_ROUTE_MAX_COOLDOWN);
            s.next_attempt = Instant::now() + *cooldown_interval;
            s.consecutive_fails = min(
                s.consecutive_fails.saturating_add(1),
                (CONNECTION_ROUTE_COOLDOWN_INTERVALS.len() - 1)
                    .try_into()
                    .unwrap(),
            );
        }
        s
    }
}

/// A connection manager that only attempts one route (i.e. one [ConnectionParams])
/// but keeps track of consecutive failed attempts and after each failure waits for a duration
/// chosen according to [CONNECTION_ROUTE_COOLDOWN_INTERVALS] list.
#[derive(Clone)]
pub struct SingleRouteThrottlingConnectionManager<C = ConnectionParams> {
    state: Arc<Mutex<ThrottlingConnectionManagerState>>,
    connection_params: C,
    connection_timeout: Duration,
}

/// A connection manager that holds a list of [SingleRouteThrottlingConnectionManager] instances
/// and iterates over them until it can find one that results in a successful connection attempt.
/// If none did, it will return [ConnectionAttemptOutcome::WaitUntil] with the minimum possible
/// cooldown time (based on cooldown times returned by all throttling connection managers).
#[derive(Clone)]
pub struct MultiRouteConnectionManager<M = SingleRouteThrottlingConnectionManager> {
    route_managers: Vec<M>,
}

impl<M> MultiRouteConnectionManager<M> {
    pub fn new(route_managers: Vec<M>) -> Self {
        Self { route_managers }
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
        E: Send + Debug + LogSafeDisplay + ErrorClassifier,
        Fun: Fn(&'a ConnectionParams) -> Fut + Send + Sync,
        Fut: Future<Output = Result<T, E>> + Send,
    {
        let mut wait_until = None;
        for route_manager in self.route_managers.iter() {
            match retry_connect_until_cooldown(route_manager, &connection_fn).await {
                Ok(t) => return ConnectionAttemptOutcome::Attempted(Ok(t)),
                Err(RetryError::WaitUntil(i)) => {
                    wait_until = Some(
                        wait_until.map_or(i, |earliest_retry| Instant::min(i, earliest_retry)),
                    );
                }
                Err(RetryError::Fatal(e)) => return ConnectionAttemptOutcome::Attempted(Err(e)),
            }
        }
        wait_until.map_or(
            ConnectionAttemptOutcome::TimedOut,
            ConnectionAttemptOutcome::WaitUntil,
        )
    }

    fn describe_for_logging(&self) -> String {
        format!(
            "multi-route: [{}]",
            self.route_managers
                .iter()
                .map(ConnectionManager::describe_for_logging)
                .join(", ")
        )
    }
}

pub enum RetryError<E> {
    /// Connection can be attempted again at a given Instant
    WaitUntil(Instant),
    /// Connection failed due to an issue that retries will not solve
    Fatal(E),
}

/// Classification of connection errors by fatality.
#[cfg_attr(test, derive(Clone, Copy))]
#[derive(Debug)]
pub enum ErrorClass {
    /// Non-fatal, somewhat counterintuitively unreachable server is a non-fatal error at this level
    /// as other connection parameters can still result in a successful connection.
    Intermittent,
    /// Fatal errors with a known retry-after value. For situations when we can reach the server,
    /// but it replies with a 429-Too Many Requests _and_ a recommended delay before any retries.
    RetryAt(Instant),
    /// Server can be reached at a lower level of net stack (TCP), but responds with an error while
    /// establishing connection at a higher level (HTTP, WebSocket, etc.)
    Fatal,
}

pub trait ErrorClassifier {
    fn classify(&self) -> ErrorClass;
}

async fn retry_connect_until_cooldown<'a, T, E, Fun, Fut>(
    route_manager: &'a impl ConnectionManager,
    connection_fn: &Fun,
) -> Result<T, RetryError<E>>
where
    T: Send,
    E: Send + Debug + LogSafeDisplay + ErrorClassifier,
    Fun: Fn(&'a ConnectionParams) -> Fut + Send + Sync,
    Fut: Future<Output = Result<T, E>> + Send,
{
    loop {
        let result = route_manager.connect_or_wait(connection_fn).await;
        match result {
            ConnectionAttemptOutcome::Attempted(Ok(r)) => {
                return Ok(r);
            }
            ConnectionAttemptOutcome::Attempted(Err(e)) => {
                let log_error = || {
                    log::debug!("Connection attempt failed with a non-fatal error: {:?}", e);
                    log::info!(
                        "Connection attempt failed with an error: {} ({})",
                        e,
                        route_manager.describe_for_logging(),
                    );
                };
                match e.classify() {
                    ErrorClass::Fatal => return Err(RetryError::Fatal(e)),
                    ErrorClass::Intermittent => {
                        log_error();
                        continue;
                    }
                    ErrorClass::RetryAt(when) => {
                        log_error();
                        return Err(RetryError::WaitUntil(when));
                    }
                }
            }
            ConnectionAttemptOutcome::TimedOut => {
                log::info!(
                    "Connection attempt timed out ({:?})",
                    route_manager.describe_for_logging()
                );
                continue;
            }
            ConnectionAttemptOutcome::WaitUntil(i) => return Err(RetryError::WaitUntil(i)),
        }
    }
}

impl<C> SingleRouteThrottlingConnectionManager<C> {
    pub fn new(connection_params: C, connection_timeout: Duration) -> Self {
        Self {
            connection_params,
            connection_timeout,
            state: Arc::new(Mutex::new(ThrottlingConnectionManagerState {
                consecutive_fails: 0,
                next_attempt: Instant::now(),
                latest_attempt: Instant::now() - Duration::from_nanos(1),
            })),
        }
    }

    pub(crate) async fn connect_or_wait<'a, T, E, Fun, Fut>(
        &'a self,
        connection_fn: Fun,
    ) -> ConnectionAttemptOutcome<T, E>
    where
        T: Send,
        E: Send,
        Fun: Fn(&'a C) -> Fut + Send + Sync,
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
        self.connect_or_wait(connection_fn).await
    }

    fn describe_for_logging(&self) -> String {
        self.connection_params.route_type.to_string()
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Borrow;
    use std::fmt::{Display, Formatter};
    use std::future;
    use std::sync::atomic::{AtomicU16, Ordering};

    use assert_matches::assert_matches;
    use nonzero_ext::nonzero;
    use tokio::time;

    use crate::infra::certs::RootCertificates;
    use crate::infra::test::shared::{
        TestError, FEW_ATTEMPTS, LONG_CONNECTION_TIME, MANY_ATTEMPTS, TIMEOUT_DURATION,
        TIME_ADVANCE_VALUE,
    };
    use crate::infra::{HttpRequestDecoratorSeq, RouteType};

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
        time::advance(CONNECTION_ROUTE_MAX_COOLDOWN).await;
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
        let multi_route_manager = MultiRouteConnectionManager::new(vec![manager_1, manager_2]);

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
        time::advance(CONNECTION_ROUTE_MAX_COOLDOWN).await;
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
        let multi_route_manager =
            MultiRouteConnectionManager::new(vec![timing_out_route_manager, manager_1]);

        time::advance(TIME_ADVANCE_VALUE).await;
        validate_expected_route(&multi_route_manager, true, ROUTE_1).await;
    }

    #[derive(Clone, Debug)]
    struct CooldownAfterSomeAttempts {
        attempts_until_cooldown: u16,
        attempts_made: Arc<AtomicU16>,
        connection_params: ConnectionParams,
    }

    impl CooldownAfterSomeAttempts {
        fn new(attempts_until_cooldown: u16, connection_params: ConnectionParams) -> Self {
            Self {
                attempts_until_cooldown,
                connection_params,
                attempts_made: Arc::new(Default::default()),
            }
        }
    }

    #[async_trait]
    impl ConnectionManager for CooldownAfterSomeAttempts {
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
            match self.attempts_made.fetch_add(1, Ordering::Relaxed) {
                n if n < self.attempts_until_cooldown => ConnectionAttemptOutcome::Attempted(
                    connection_fn(&self.connection_params).await,
                ),
                _ => ConnectionAttemptOutcome::WaitUntil(
                    Instant::now() + CONNECTION_ROUTE_MAX_COOLDOWN,
                ),
            }
        }

        fn describe_for_logging(&self) -> String {
            format!("{self:?}")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn multi_route_manager_retries_the_same_option_until_cooldown() {
        let route_1 = example_connection_params(ROUTE_1);
        let route_2 = example_connection_params(ROUTE_2);
        let route_1_attempts_until_cooldown = 2;
        let route_2_attempts_until_cooldown = 1;
        let route_1_manager =
            CooldownAfterSomeAttempts::new(route_1_attempts_until_cooldown, route_1.clone());
        let route_2_manager =
            CooldownAfterSomeAttempts::new(route_2_attempts_until_cooldown, route_2.clone());
        let multi_route_manager = MultiRouteConnectionManager::new(vec![
            route_1_manager.clone(),
            route_2_manager.clone(),
        ]);
        let route_1_attempt = AtomicU16::new(1);
        let res = multi_route_manager
            .connect_or_wait(|connection_params| {
                // route_1 only connects when there is one attempt left before the cooldown
                //
                // note: route_2 is always healthy, the flag only affects route_1
                let route_1_healthy = route_1_attempt.fetch_add(1, Ordering::Relaxed)
                    == route_1_attempts_until_cooldown;

                simulate_connect(connection_params, route_1_healthy)
            })
            .await;

        assert_matches!(res, ConnectionAttemptOutcome::Attempted(Ok(r)) if r == ROUTE_1);
        assert_eq!(
            route_1_attempts_until_cooldown,
            route_1_manager.attempts_made.load(Ordering::Relaxed)
        );
        assert_eq!(0, route_2_manager.attempts_made.load(Ordering::Relaxed));
    }

    #[derive(Copy, Clone, Debug)]
    struct AlwaysInCooldown {
        wait: Duration,
    }

    #[async_trait]
    impl ConnectionManager for AlwaysInCooldown {
        async fn connect_or_wait<'a, T, E, Fun, Fut>(
            &'a self,
            _connection_fn: Fun,
        ) -> ConnectionAttemptOutcome<T, E>
        where
            T: Send,
            E: Send + Debug + LogSafeDisplay,
            Fun: Fn(&'a ConnectionParams) -> Fut + Send + Sync,
            Fut: Future<Output = Result<T, E>> + Send,
        {
            ConnectionAttemptOutcome::WaitUntil(Instant::now() + self.wait)
        }

        fn describe_for_logging(&self) -> String {
            format!("{self:?}")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn multi_route_manager_attempt_to_connect_until_all_routes_in_cooldown() {
        let connection_params = example_connection_params(ROUTE_1);
        let first_manager_attempts_until_cooldown = 5;
        let second_manager_attempts_until_cooldown = 3;
        let first_manager = CooldownAfterSomeAttempts::new(
            first_manager_attempts_until_cooldown,
            connection_params.clone(),
        );
        let second_manager = CooldownAfterSomeAttempts::new(
            second_manager_attempts_until_cooldown,
            connection_params,
        );
        let multi_route_manager =
            MultiRouteConnectionManager::new(vec![first_manager.clone(), second_manager.clone()]);
        let res = multi_route_manager
            .connect_or_wait(|connection_params| simulate_connect(connection_params, false))
            .await;
        assert_matches!(res, ConnectionAttemptOutcome::WaitUntil(_));
        assert_eq!(
            first_manager_attempts_until_cooldown + 1,
            first_manager.attempts_made.load(Ordering::Relaxed)
        );
        assert_eq!(
            second_manager_attempts_until_cooldown + 1,
            second_manager.attempts_made.load(Ordering::Relaxed)
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn multi_route_manager_all_in_cooldown() {
        const SHORT_DELAY: Duration = Duration::from_secs(5);
        const LONG_DELAY: Duration = Duration::from_secs(100);
        let multi_route_manager = MultiRouteConnectionManager::new(vec![
            AlwaysInCooldown { wait: LONG_DELAY },
            AlwaysInCooldown { wait: SHORT_DELAY },
        ]);

        let now = Instant::now();
        let attempt_outcome: ConnectionAttemptOutcome<&str, TestError> = multi_route_manager
            .connect_or_wait(|connection_params| simulate_connect(connection_params, true))
            .await;
        let wait_until =
            assert_matches!(attempt_outcome, ConnectionAttemptOutcome::WaitUntil(t) => t);
        assert_eq!(wait_until, now + SHORT_DELAY);
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
            RouteType::Test,
            host,
            host,
            nonzero!(443u16),
            HttpRequestDecoratorSeq::default(),
            RootCertificates::Signal,
        )
    }

    #[derive(Debug)]
    struct ClassifiableTestError(ErrorClass);

    impl ErrorClassifier for ClassifiableTestError {
        fn classify(&self) -> ErrorClass {
            self.0
        }
    }

    impl Display for ClassifiableTestError {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }

    impl LogSafeDisplay for ClassifiableTestError {}

    #[derive(Clone, Debug)]
    struct FailingSingle(ConnectionParams);

    #[async_trait]
    impl ConnectionManager for FailingSingle {
        async fn connect_or_wait<'a, T, E, Fun, Fut>(
            &'a self,
            connection_fn: Fun,
        ) -> ConnectionAttemptOutcome<T, E>
        where
            T: Send,
            E: Send + Debug + LogSafeDisplay + ErrorClassifier,
            Fun: Fn(&'a ConnectionParams) -> Fut + Send + Sync,
            Fut: Future<Output = Result<T, E>> + Send,
        {
            ConnectionAttemptOutcome::Attempted(connection_fn(&self.0).await)
        }

        fn describe_for_logging(&self) -> String {
            format!("{self:?}")
        }
    }

    #[tokio::test(start_paused = true)]
    async fn multi_route_manager_should_short_circuit_on_fatal_errors() {
        let first_manager = FailingSingle(example_connection_params(ROUTE_1));
        let second_manager = FailingSingle(example_connection_params(ROUTE_2));

        let multi_route_manager =
            MultiRouteConnectionManager::new(vec![first_manager.clone(), second_manager.clone()]);
        let res: ConnectionAttemptOutcome<(), ClassifiableTestError> = multi_route_manager
            .connect_or_wait(|connection_params| {
                assert_ne!(
                    *connection_params.host, *ROUTE_2,
                    "Should not attempt second route if the first one was fatal"
                );
                future::ready(Err(ClassifiableTestError(ErrorClass::Fatal)))
            })
            .await;
        assert_matches!(
            res,
            ConnectionAttemptOutcome::Attempted(Err(ClassifiableTestError(ErrorClass::Fatal)))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn multi_route_manager_should_respect_retry_after() {
        let first_manager = FailingSingle(example_connection_params(ROUTE_1));

        let retry_at = Instant::now() + Duration::from_secs(42);
        let multi_route_manager = MultiRouteConnectionManager::new(vec![first_manager.clone()]);
        let res: ConnectionAttemptOutcome<(), ClassifiableTestError> = multi_route_manager
            .connect_or_wait(|_connection_params| {
                future::ready(Err(ClassifiableTestError(ErrorClass::RetryAt(retry_at))))
            })
            .await;
        assert_matches!(res, ConnectionAttemptOutcome::WaitUntil(instant) => {
            assert_eq!(instant, retry_at)
        });
    }
}
