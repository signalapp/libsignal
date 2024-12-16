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
use itertools::Itertools;
use tokio::sync::Mutex;
use tokio::time::{timeout_at, Instant};

use crate::errors::LogSafeDisplay;
use crate::timeouts::{CONNECTION_ROUTE_COOLDOWN_INTERVALS, CONNECTION_ROUTE_MAX_COOLDOWN};
use crate::utils::{EventSubscription, ObservableEvent};
use crate::ConnectionParams;

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

/// Policy object that decides how and when to connect.
///
/// Encapsulates the logic that, for a given connection attempt, decides whether
/// an attempt is to be made in the first place, and, if yes, which
/// [`ConnectionParams`] are to be used for the attempt.
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
    #[cfg(test)]
    reset_counter: u8,
}

impl ThrottlingConnectionManagerState {
    fn new(now: Instant) -> Self {
        Self {
            consecutive_fails: 0,
            next_attempt: now,
            latest_attempt: now - Duration::from_nanos(1),
            #[cfg(test)]
            reset_counter: 0,
        }
    }

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

    /// Reset the state after a network change event.
    fn network_changed(&mut self, network_change_time: Instant) {
        #[cfg(test)]
        {
            self.reset_counter = self.reset_counter.saturating_add(1);
        }

        if self.consecutive_fails == 0 {
            // Easy case: the most recent attempt has been successful, so there's currently no
            // cooldown we need to reset.
            return;
        }

        let Self {
            latest_attempt,
            #[cfg(test)]
            reset_counter,
            ..
        } = std::mem::replace(self, Self::new(network_change_time));

        #[cfg(test)]
        {
            self.reset_counter = reset_counter;
        }

        if latest_attempt < network_change_time {
            // Also easy: all completed attempts were on the old network, and we can't / don't need
            // to rely on them anymore. The reset above is all we need.
            return;
        }

        // Otherwise, one or more failures have happened *since* the network change. In this case,
        // we'd *like* to reset the consecutive fails counter to the number of fails since the
        // change, but we don't have that information. Compromise by re-recording the most recent
        // attempt as a single failure.
        *self = self.clone().after_attempt(false, latest_attempt);
    }
}

/// A connection manager that only attempts one route (i.e. one [ConnectionParams]).
///
/// It keeps track of consecutive failed attempts and after each failure waits for a duration
/// chosen according to [CONNECTION_ROUTE_COOLDOWN_INTERVALS] list.
#[derive(Clone, Debug)]
pub struct SingleRouteThrottlingConnectionManager<C = ConnectionParams> {
    state: Arc<Mutex<ThrottlingConnectionManagerState>>,
    connection_params: C,
    connection_timeout: Duration,
    _network_changed_subscription: Arc<EventSubscription>,
}

/// A connection manager that holds a list of [SingleRouteThrottlingConnectionManager] instances.
///
/// It iterates over them until it can find one that results in a successful connection attempt.
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
#[cfg_attr(any(test, feature = "test-util"), derive(Clone, Copy))]
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
                let log_error = |e: &E, when: &'static str| {
                    log::debug!("Connection attempt failed with a non-fatal error: {e:?}, will retry {when}");
                    log::info!(
                        "Connection attempt failed with an error: {} ({})",
                        e,
                        route_manager.describe_for_logging(),
                    );
                };
                match e.classify() {
                    ErrorClass::Fatal => return Err(RetryError::Fatal(e)),
                    ErrorClass::Intermittent => {
                        log_error(&e, "immediately");
                        continue;
                    }
                    ErrorClass::RetryAt(when) => {
                        log_error(&e, "soon");
                        // A RetryAt means that this route *should* work, and no route will work
                        // sooner than this. So we don't return.
                        // FIXME: This isn't ideal, because there might be a higher-level timeout
                        // that gives up, and that higher-level operation won't be informed of the
                        // RetryAt. We can revisit that in the ws2 implementation.
                        tokio::time::sleep_until(when).await;
                        continue;
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
    pub fn new(
        connection_params: C,
        connection_timeout: Duration,
        network_changed_event: &ObservableEvent,
    ) -> Self {
        let now = Instant::now();
        let state = Arc::new(Mutex::new(ThrottlingConnectionManagerState::new(now)));

        // Make sure that we don't have a reference cycle subscribing to the network change event:
        // - the connection manager's subscription to the event will live as long as it does...
        // - but the subscription alone shouldn't keep the connection manager state alive.
        // This isn't strictly necessary because the subscription isn't stored in the shared state,
        // but it hedges against future refactorings, and is a safer pattern in general when
        // ignoring a callback during teardown is the right thing to do.
        let state_for_network_changed = Arc::downgrade(&state);
        let network_changed_subscription = network_changed_event.subscribe(Box::new(move || {
            let Some(state) = state_for_network_changed.upgrade() else {
                return;
            };
            let time_of_event = Instant::now();
            // We'd like to reset the cooldowns synchronously, but tokio won't let us block on an
            // async-aware mutex if we're currently within an async runtime. Spawn a task to do the
            // reset ASAP instead.
            if let Ok(tokio_runtime) = tokio::runtime::Handle::try_current() {
                tokio_runtime.spawn(async move {
                    state.lock().await.network_changed(time_of_event);
                });
            } else {
                state.blocking_lock().network_changed(time_of_event);
            }
        }));

        Self {
            connection_params,
            connection_timeout,
            state,
            _network_changed_subscription: Arc::new(network_changed_subscription),
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
            .is_ok_and(|r| r.is_ok());
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
    use std::future;
    use std::sync::atomic::{AtomicU16, Ordering};

    use assert_matches::assert_matches;
    use nonzero_ext::nonzero;
    use tokio::time;

    use super::*;
    use crate::certs::RootCertificates;
    use crate::host::Host;
    use crate::testutil::{
        ClassifiableTestError, TestError, FEW_ATTEMPTS, LONG_CONNECTION_TIME, MANY_ATTEMPTS,
        TIMEOUT_DURATION, TIME_ADVANCE_VALUE,
    };
    use crate::{HttpRequestDecoratorSeq, RouteType, TransportConnectionParams};

    const ROUTE_THAT_TIMES_OUT: &str = "timeout.signal.org";

    const ROUTE_1: &str = "route1.signal.org";

    const ROUTE_2: &str = "route2.signal.org";

    #[tokio::test]
    async fn single_route_successfull_attempts() {
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params("chat.staging.signal.org"),
            TIMEOUT_DURATION,
            &ObservableEvent::default(),
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
            &ObservableEvent::default(),
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
            &ObservableEvent::default(),
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
            &ObservableEvent::default(),
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
    async fn single_route_manager_resets_cooldown_on_network_changed() {
        let network_changed_event = ObservableEvent::default();
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params("chat.staging.signal.org"),
            TIMEOUT_DURATION,
            &network_changed_event,
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

        // Wait a bit, but not long enough that the cooldown should have elapsed.
        time::advance(TIME_ADVANCE_VALUE).await;
        network_changed_event.fire();
        // At this point the cooldown reset task has been spawned, but not run.
        // Yielding does not guarantee that tokio will execute it, but it does make it very likely,
        // especially on the current_thread runtime.
        tokio::task::yield_now().await;
        assert_eq!(manager.state.lock().await.reset_counter, 1);

        let attempt_outcome: ConnectionAttemptOutcome<(), TestError> =
            manager.connect_or_wait(|_| future::ready(Ok(()))).await;
        assert_matches!(attempt_outcome, ConnectionAttemptOutcome::Attempted(Ok(())));
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn single_route_manager_resets_cooldown_count_on_network_changed() {
        let network_changed_event = ObservableEvent::default();
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params("chat.staging.signal.org"),
            TIMEOUT_DURATION,
            &network_changed_event,
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

        // Wait a bit, but not long enough that the cooldown should have elapsed.
        time::advance(TIME_ADVANCE_VALUE).await;
        network_changed_event.fire();
        // At this point the cooldown reset task has been spawned, but not run.
        // Yielding does not guarantee that tokio will execute it, but it does make it very likely,
        // especially on the current_thread runtime.
        tokio::task::yield_now().await;
        assert_eq!(manager.state.lock().await.reset_counter, 1);

        // first attempt after network change
        let time_over_timeout = TIMEOUT_DURATION * 2;
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
        assert_matches!(
            attempt_outcome,
            ConnectionAttemptOutcome::WaitUntil(later)
            if later
                .checked_duration_since(Instant::now())
                .expect("future")
                <= CONNECTION_ROUTE_COOLDOWN_INTERVALS[1]
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn network_resets_consider_latest_attempt_time() {
        let mut state = ThrottlingConnectionManagerState::new(Instant::now());
        state = state.clone().after_attempt(false, Instant::now());
        assert_eq!(state.consecutive_fails, 1);
        assert_eq!(state.reset_counter, 0);

        time::advance(TIME_ADVANCE_VALUE).await;
        state.network_changed(Instant::now());
        assert_eq!(state.consecutive_fails, 0);
        assert_eq!(state.next_attempt, Instant::now());

        time::advance(TIME_ADVANCE_VALUE).await;
        state = state.clone().after_attempt(false, Instant::now());
        assert_eq!(state.consecutive_fails, 1);

        time::advance(TIME_ADVANCE_VALUE).await;
        let network_change_time = Instant::now();

        time::advance(TIME_ADVANCE_VALUE).await;
        state = state.clone().after_attempt(false, Instant::now());
        assert_eq!(state.consecutive_fails, 2);

        time::advance(TIME_ADVANCE_VALUE).await;
        state = state.clone().after_attempt(false, Instant::now());
        assert_eq!(state.consecutive_fails, 3);

        time::advance(TIME_ADVANCE_VALUE).await;
        let latest_attempt = state.latest_attempt;
        state.network_changed(network_change_time);
        // There were two failures after the network change, but we lost that information.
        // (If we are more precise in the future, please update this test accordingly.)
        assert_eq!(state.consecutive_fails, 1);
        assert_eq!(state.latest_attempt, latest_attempt);
        assert_eq!(
            state.next_attempt,
            Instant::now() + CONNECTION_ROUTE_COOLDOWN_INTERVALS[0]
        );
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn multi_route_manager_picks_working_route() {
        let manager_1 = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(ROUTE_1),
            TIMEOUT_DURATION,
            &ObservableEvent::default(),
        );
        let manager_2 = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(ROUTE_2),
            TIMEOUT_DURATION,
            &ObservableEvent::default(),
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
            &ObservableEvent::default(),
        );
        let manager_1 = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(ROUTE_1),
            TIMEOUT_DURATION,
            &ObservableEvent::default(),
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

                simulate_connect(
                    connection_params,
                    if route_1_healthy {
                        None
                    } else {
                        Some(TestError::Expected)
                    },
                )
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
            .connect_or_wait(|connection_params| {
                simulate_connect(connection_params, Some(TestError::Expected))
            })
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

    #[tokio::test(start_paused = true)]
    async fn multi_route_manager_propagates_post_connection_failure() {
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
            .connect_or_wait(|connection_params| {
                simulate_connect(
                    connection_params,
                    Some(ClassifiableTestError(ErrorClass::Fatal)),
                )
            })
            .await;
        assert_matches!(
            res,
            ConnectionAttemptOutcome::Attempted(Err(ClassifiableTestError(ErrorClass::Fatal)))
        );
        assert_eq!(1, first_manager.attempts_made.load(Ordering::Relaxed));
        assert_eq!(0, second_manager.attempts_made.load(Ordering::Relaxed));
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
            .connect_or_wait(|connection_params| {
                simulate_connect(connection_params, Some(TestError::Expected))
            })
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
                simulate_connect(
                    connection_params,
                    if route1_healthy {
                        None
                    } else {
                        Some(TestError::Expected)
                    },
                )
                .await
            })
            .await;
        assert_matches!(
            attempt_outcome,
            ConnectionAttemptOutcome::Attempted(Ok(a)) if a == expected_route
        );
    }

    async fn simulate_connect<E>(
        connection_params: &ConnectionParams,
        route1_error: Option<E>,
    ) -> Result<&str, E> {
        let route1_response = match route1_error {
            None => Ok(ROUTE_1),
            Some(err) => Err(err),
        };
        let domain = match &connection_params.transport.tcp_host {
            Host::Domain(domain) => &**domain,
            h => panic!("unexpected host {h}"),
        };
        match domain {
            ROUTE_1 => future::ready(route1_response).await,
            ROUTE_2 => future::ready(Ok(ROUTE_2)).await,
            ROUTE_THAT_TIMES_OUT => {
                tokio::time::sleep(LONG_CONNECTION_TIME).await;
                future::ready(Ok(ROUTE_THAT_TIMES_OUT)).await
            }
            _ => panic!("not configured for the route"),
        }
    }

    fn example_connection_params(host: &str) -> ConnectionParams {
        let host = host.into();
        ConnectionParams {
            route_type: RouteType::Test,
            transport: TransportConnectionParams {
                sni: Arc::clone(&host),
                tcp_host: Host::Domain(Arc::clone(&host)),
                certs: RootCertificates::Native,
                port: nonzero!(443u16),
            },
            http_host: host,
            http_request_decorator: HttpRequestDecoratorSeq::default(),
            connection_confirmation_header: None,
        }
    }

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
                    connection_params.transport.tcp_host.as_deref(),
                    Host::Domain(ROUTE_2),
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
                let e = if Instant::now() < retry_at {
                    ClassifiableTestError(ErrorClass::RetryAt(retry_at))
                } else {
                    ClassifiableTestError(ErrorClass::Fatal)
                };
                future::ready(Err(e))
            })
            .await;
        assert_matches!(
            res,
            ConnectionAttemptOutcome::Attempted(Err(ClassifiableTestError(ErrorClass::Fatal)))
        );
        assert_eq!(Instant::now(), retry_at);
    }
}
