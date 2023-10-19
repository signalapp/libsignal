//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cmp::max;
use std::fmt::Debug;
use std::future::Future;
use std::ops::Add;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::infra::errors::LogSafeDisplay;
use crate::infra::ConnectionParams;

const MAX_COOLDOWN_INTERVAL: Duration = Duration::from_secs(64);

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

pub enum ConnectionAttemptOutcome<T, E> {
    Attempted(Result<T, E>),
    WaitUntil(Instant),
}

/// Encapsulates the logic that for every connection attempt decides
/// whether or not an attempt is to be made in the first place, and, if yes,
/// which [ConnectionParams] are to be used for the attempt.
#[async_trait]
pub trait ConnectionManager: Send + Sync {
    async fn connect_or_wait<'a, T, E, Fun, Fut>(
        &'a self,
        connection_fn: &Fun,
    ) -> ConnectionAttemptOutcome<T, E>
    where
        T: Send,
        E: Send + Debug + LogSafeDisplay,
        Fun: Fn(&'a ConnectionParams) -> Fut + Send + Sync,
        Fut: Future<Output = Result<T, E>> + Send;
}

#[derive(Clone, Debug)]
struct ThrottlingConnectionManagerState {
    consecutive_fails: u16,
    next_attempt: Instant,
    latest_attempt: Instant,
}

/// A connection manager that only attempts one route (i.e. one [ConnectionParams])
/// but keeps track of consecutive failed attempts and after each failure waits for a duration
/// chosen according to [COOLDOWN_INTERVALS] list.
#[derive(Clone)]
pub struct SingleRouteThrottlingConnectionManager {
    state: Arc<Mutex<ThrottlingConnectionManagerState>>,
    connection_params: ConnectionParams,
}

/// A connection manager that holds a list of [SingleRouteThrottlingConnectionManager] instances
/// and itereates over them until it can find one that results in a successful connection attempt.
/// If none did, it will return [ConnectionAttemptOutcome::WaitUntil] with the minimum possible
/// cooldown time (based on cooldown times returned by all throttling connection managers).
#[derive(Clone)]
pub struct MultiRouteConnectionManager {
    route_managers: Vec<SingleRouteThrottlingConnectionManager>,
}

impl MultiRouteConnectionManager {
    pub fn new(route_managers: Vec<SingleRouteThrottlingConnectionManager>) -> Self {
        Self { route_managers }
    }
}

#[async_trait]
impl ConnectionManager for MultiRouteConnectionManager {
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
        connection_fn: &Fun,
    ) -> ConnectionAttemptOutcome<T, E>
    where
        T: Send,
        E: Send + Debug + LogSafeDisplay,
        Fun: Fn(&'a ConnectionParams) -> Fut + Send + Sync,
        Fut: Future<Output = Result<T, E>> + Send,
    {
        let mut earliest_retry = Instant::now() + MAX_COOLDOWN_INTERVAL;
        for route_manager in self.route_managers.iter() {
            loop {
                match route_manager.connect_or_wait(connection_fn).await {
                    ConnectionAttemptOutcome::Attempted(Ok(r)) => {
                        return ConnectionAttemptOutcome::Attempted(Ok(r));
                    }
                    ConnectionAttemptOutcome::Attempted(Err(e)) => {
                        log::debug!("Connection attempt failed with an error: {:?}", e);
                        log::info!("Connection attempt failed with an error: {}", e);
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
    pub fn new(connection_params: ConnectionParams) -> Self {
        Self {
            connection_params,
            state: Arc::new(Mutex::new(ThrottlingConnectionManagerState {
                consecutive_fails: 0,
                next_attempt: Instant::now(),
                latest_attempt: Instant::now(),
            })),
        }
    }
}

#[async_trait]
impl ConnectionManager for SingleRouteThrottlingConnectionManager {
    async fn connect_or_wait<'a, T, E, Fun, Fut>(
        &'a self,
        connection_fn: &Fun,
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
        let connection_result = connection_fn(&self.connection_params).await;

        let s = &mut self.state.lock().await;
        // The logic here is that we will track an attempt start time
        // and we will take it into account when updating the state.
        // Then, if we see failed attempts that started before some successful attempt,
        // those failed attempts are discarded. If, however, outcomes of failed attempts
        // are arriving out of order in which attempts started,
        // those failures will still be reflected in `consecutive_fails`.
        match &connection_result {
            Ok(_) => {
                // comparing wiht `>=` to guarantee that succesful attempt takes precedence
                if attempt_start_time >= s.latest_attempt {
                    s.latest_attempt = attempt_start_time;
                    s.consecutive_fails = 0;
                    s.next_attempt = attempt_start_time;
                }
            }
            Err(_) => {
                if attempt_start_time > s.latest_attempt || s.consecutive_fails > 0 {
                    s.latest_attempt = max(attempt_start_time, s.latest_attempt);
                    let idx: usize = s.consecutive_fails.into();
                    let cooldown_interval = COOLDOWN_INTERVALS
                        .get(idx)
                        .unwrap_or(&MAX_COOLDOWN_INTERVAL);
                    s.next_attempt = Instant::now().add(*cooldown_interval);
                    s.consecutive_fails = s.consecutive_fails.saturating_add(1);
                }
            }
        }
        ConnectionAttemptOutcome::Attempted(connection_result)
    }
}
