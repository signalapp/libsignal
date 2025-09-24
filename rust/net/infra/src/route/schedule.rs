//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::future::Future;
use std::hash::Hash;
use std::pin::Pin;
use std::sync::Arc;
use std::time::SystemTime;

use derive_where::derive_where;
use futures_util::stream::{FusedStream, FuturesUnordered};
use futures_util::{Stream, StreamExt};
use pin_project::pin_project;
use rangemap::RangeSet;
use tokio::time::{Duration, Instant};

use crate::dns::DnsError;
use crate::dns::dns_utils::log_safe_domain;
use crate::route::{ResolveHostnames, ResolvedRoute, Resolver, TransportRoute, UsesTransport};
use crate::utils::NetworkChangeEvent;
use crate::utils::binary_heap::{MinKeyValueQueue, Queue};
use crate::utils::future::SomeOrPending;

/// Resolves routes with domain names to equivalent routes with IP addresses.
///
/// [`RouteResolver::resolve`] is the main entry point; this type exists mostly
/// to provide some named state that is used as input to that function.
#[derive(Clone)]
pub struct RouteResolver {
    pub allow_ipv6: bool,
}

/// A policy object that decides how much to delay a route.
pub trait RouteDelayPolicy<R> {
    /// Given a route, how much should it be delayed by?
    fn compute_delay(&self, route: &R, now: Instant) -> Duration;

    /// Produces a future that completes when the RouteDelayPolicy wants to indicate that its
    /// previous delays are no longer accurate.
    ///
    /// This future should be "cancel-safe"; if it's ready but not polled to completion, the next
    /// call to `wants_recalculation` should produce a ready future immediately.
    fn wants_recalculation(&mut self) -> impl Future<Output = ()> + '_ {
        std::future::pending()
    }
}

/// Metadata about a resolved route.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResolveMeta {
    /// The position of the un-resolved route in the source input stream.
    original_group_index: usize,
}

/// Schedules resolved routes for connection attempts in priority order.
///
/// This is notionally a stream, though it doesn't (yet) implement [`Stream`].
/// [`Schedule::next`] behaves like [`StreamExt::next`]. The output of calling
/// `next` is a sequence of routes to attempt connecting over, in the order in
/// which they should be tried.
///
/// Internally, this is implemented with two min-heaps: one that orders
/// [`ResolvedRoutes`] (groups of routes from the same unresolved route) by
/// their original order in the input, and a second that orders individual
/// routes by the time at which they should be attempted (based on the
/// [`RouteDelayPolicy`] provided).
#[derive(Debug)]
#[pin_project(project=ScheduleProj)]
pub struct Schedule<S, R, SP> {
    #[pin]
    resolver_stream: MinKeyValueQueueStream<SwapPairStream<S>, ResolveMeta, ResolvedRoutes<R>>,
    scoring_policy: SP,

    delayed_individual_routes: MinKeyValueQueue<IndividualRouteKey, R>,
    #[pin]
    individual_routes_sleep: tokio::time::Sleep,
}

/// Record of recent connection outcomes.
///
/// Implements [`RouteDelayPolicy`].
#[derive(Clone)]
pub struct ConnectionOutcomes<R> {
    params: ConnectionOutcomeParams,
    recent_failures: HashMap<R, ConnectionFailureRecord>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ConnectionOutcomeParams {
    pub short_term_age_cutoff: Duration,
    pub long_term_age_cutoff: Duration,
    pub cooldown_growth_factor: f32,
    pub count_growth_factor: f32,
    pub max_count: u8,
    pub max_delay: Duration,
}

#[derive(Clone)]
struct ConnectionFailureRecord {
    outcome: UnsuccessfulOutcome,
    started: Instant,
    wall_clock: SystemTime,
    failure_count: u8,
}

impl Default for RouteResolver {
    fn default() -> Self {
        Self { allow_ipv6: true }
    }
}

impl RouteResolver {
    /// Resolve an ordered sequence of routes with hostnames as a stream of
    /// resolved routes.
    ///
    /// Produces a sequence of [`ResolvedRoutes`] in roughly priority order by
    /// resolving the hostnames in each of the input routes. Each input route
    /// corresponds to a single `ResolvedRoutes` in the output, though not
    /// necessarily in the same order as the input sequence. The order is
    /// maintained as much as possible subject to delays in name resolution.
    pub fn resolve<'r, R>(
        &'r self,
        ordered_routes: impl Iterator<Item = R> + 'r,
        resolver: &'r impl Resolver,
    ) -> impl FusedStream<Item = (ResolvedRoutes<R::Resolved>, ResolveMeta)> + 'r
    where
        R: ResolveHostnames<Resolved: ResolvedRoute> + Clone + 'static,
    {
        let Self { allow_ipv6 } = self;

        let resolved = eagerly_resolve_each(ordered_routes, resolver).filter_map(
            |(resolution_result, meta)| {
                std::future::ready(match resolution_result {
                    Ok(route_group) => Some((route_group, meta)),
                    Err((name, err)) => {
                        log::warn!(
                            "DNS resolution for {name} failed: {err}",
                            name = log_safe_domain(&name)
                        );
                        None
                    }
                })
            },
        );

        // Prune routes that connect directly to IPv6 addresses if necessary.
        resolved.map(|(mut routes, meta)| {
            if !*allow_ipv6 {
                routes
                    .routes
                    .retain(|route| route.immediate_target().is_ipv4())
            }
            (routes, meta)
        })
    }
}

#[derive(Default)]
pub struct ScheduleStatus {
    waiting_on_resolution: bool,
    scheduled_route_count: usize,
    scheduled_route_cooldown: Duration,
}

impl Display for ScheduleStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.waiting_on_resolution, self.scheduled_route_count) {
            (false, 0) => write!(f, "no more routes"),
            (false, count) => write!(
                f,
                "{count} route(s) delayed for another {:.2?}",
                self.scheduled_route_cooldown
            ),
            (true, 0) => write!(f, "more routes waiting on DNS resolution"),
            (true, count) => write!(
                f,
                "{count} route(s) delayed for {:.2?}, more waiting on DNS resolution",
                self.scheduled_route_cooldown
            ),
        }
    }
}

impl<S, R, SP> Schedule<S, R, SP>
where
    S: FusedStream<Item = (ResolvedRoutes<R>, ResolveMeta)>,
    SP: RouteDelayPolicy<R>,
{
    pub fn new(
        resolver_stream: S,
        previous_attempts: SP,
        out_of_order_debounce_time: Duration,
    ) -> Self {
        Self {
            resolver_stream: MinKeyValueQueueStream::new(
                SwapPairStream(resolver_stream),
                out_of_order_debounce_time,
            ),
            delayed_individual_routes: MinKeyValueQueue::new(),
            scoring_policy: previous_attempts,
            individual_routes_sleep: tokio::time::sleep(Duration::ZERO),
        }
    }

    /// Returns the next route to try, or `None` if all routes are exhausted.
    ///
    /// This is functionally [`StreamExt::next`], but this type doesn't (yet)
    /// implement [`Stream`]. See the type-level documentation for the order in
    /// which this will produce routes.
    pub async fn next(self: Pin<&mut Self>) -> Option<R> {
        let ScheduleProj {
            resolver_stream,
            delayed_individual_routes,

            scoring_policy,

            mut individual_routes_sleep,
        } = self.project();

        #[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
        enum Event<T> {
            PulledFromResolver(T),
            ReturnNextIndividualRoute,
            RecalculateDelays,
        }

        let mut resolver_stream =
            resolver_stream.filter(|value| std::future::ready(!value.1.routes.is_empty()));

        loop {
            let next_from_individual_routes = delayed_individual_routes.peek().map(|(key, _)| {
                individual_routes_sleep.as_mut().reset(key.time);
                individual_routes_sleep.as_mut()
            });

            let pull_from_resolver_if_not_terminated =
                (!resolver_stream.is_terminated()).then_some(resolver_stream.next());

            if next_from_individual_routes.is_none()
                && pull_from_resolver_if_not_terminated.is_none()
            {
                return None;
            }
            let event = tokio::select! {
                () = SomeOrPending(next_from_individual_routes) => Event::ReturnNextIndividualRoute,
                route = SomeOrPending(pull_from_resolver_if_not_terminated) => Event::PulledFromResolver(route),
                () = scoring_policy.wants_recalculation() => Event::RecalculateDelays,
            };

            match event {
                Event::PulledFromResolver(Some(value)) => {
                    let (
                        ResolveMeta {
                            original_group_index,
                        },
                        routes,
                    ) = value;
                    let now = Instant::now();
                    delayed_individual_routes.extend(routes.into_iter().enumerate().map(
                        |(i, r)| {
                            let delay = HAPPY_EYEBALLS_DELAY * u32::try_from(i).unwrap_or(u32::MAX)
                                + scoring_policy.compute_delay(&r, now);
                            let key = IndividualRouteKey {
                                original_group_index,
                                resolved_index: i,
                                time: now + delay,
                            };
                            (key, r)
                        },
                    ));

                    // The routes queue was updated. Restart the loop so we can
                    // recompute the sleep timeouts.
                    continue;
                }
                Event::PulledFromResolver(None) => {
                    // We know for sure the resolver stream is terminated. Start
                    // the top of the loop again so we can check if the two
                    // queues are empty and we need to exit.
                    continue;
                }
                Event::RecalculateDelays => {
                    let now = Instant::now();
                    delayed_individual_routes.recalculate_keys(|key, route| {
                        let delay = HAPPY_EYEBALLS_DELAY
                            * u32::try_from(key.resolved_index).unwrap_or(u32::MAX)
                            + scoring_policy.compute_delay(route, now);
                        key.time = now + delay;
                    });
                    // Start over with our new delays.
                    continue;
                }
                Event::ReturnNextIndividualRoute => {
                    let next = delayed_individual_routes
                        .pop()
                        .expect("non-empty checked earlier");
                    return Some(next.1);
                }
            }
        }
    }

    pub fn status(&self) -> ScheduleStatus {
        ScheduleStatus {
            waiting_on_resolution: !self.resolver_stream.is_terminated(),
            scheduled_route_count: self.delayed_individual_routes.len(),
            scheduled_route_cooldown: self
                .delayed_individual_routes
                .peek()
                .map(|(key, _)| key.time.saturating_duration_since(Instant::now()))
                .unwrap_or_default(),
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct AttemptOutcome {
    pub started: Instant,
    pub result: Result<(), UnsuccessfulOutcome>,
}

/// Represents a failure to connect, and how long it should be remembered.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum UnsuccessfulOutcome {
    #[default]
    ShortTerm,
    LongTerm,
}

impl<R: Hash + Eq + Clone> ConnectionOutcomes<R> {
    pub fn new(params: ConnectionOutcomeParams) -> Self {
        Self {
            params,
            recent_failures: Default::default(),
        }
    }

    /// Configuration that stores no history, suitable for one-shot connections.
    pub fn for_oneshot() -> Self {
        Self::new(ConnectionOutcomeParams {
            short_term_age_cutoff: Duration::ZERO,
            long_term_age_cutoff: Duration::ZERO,
            cooldown_growth_factor: 0.0,
            count_growth_factor: 0.0,
            max_count: 0,
            max_delay: Duration::ZERO,
        })
    }

    /// Update the internal state with the results of completed connection attempts.
    pub fn apply_outcome_updates(
        &mut self,
        updates: impl IntoIterator<Item = (R, AttemptOutcome)>,
        now: Instant,
        wall_clock: SystemTime,
    ) {
        use std::collections::hash_map::Entry;

        let Self {
            params,
            recent_failures,
        } = self;

        // Age out any old entries.
        recent_failures.retain(|_route, record| {
            let ConnectionFailureRecord {
                outcome,
                started: last_time,
                wall_clock: _,
                failure_count: _,
            } = record;
            let age_cutoff = match outcome {
                UnsuccessfulOutcome::ShortTerm => params.short_term_age_cutoff,
                UnsuccessfulOutcome::LongTerm => params.long_term_age_cutoff,
            };
            now.saturating_duration_since(*last_time) < age_cutoff
        });

        for (route, outcome) in updates {
            let AttemptOutcome { started, result } = outcome;

            match result {
                Ok(()) => {
                    let _ = recent_failures.remove(&route);
                }
                Err(unsuccessful_outcome) => match recent_failures.entry(route) {
                    Entry::Occupied(mut entry) => {
                        entry.get_mut().update(
                            unsuccessful_outcome,
                            started,
                            wall_clock,
                            params.max_count,
                        );
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(ConnectionFailureRecord::new(
                            unsuccessful_outcome,
                            started,
                            wall_clock,
                        ));
                    }
                },
            }
        }
    }

    /// Clear any outcomes from before the cutoff.
    ///
    /// Assumes those that completed after the cutoff are still relevant.
    pub fn reset(&mut self, cutoff: Instant) {
        self.recent_failures
            .retain(|_route, record| cutoff < record.started);
    }

    /// Clear any outcomes that should have expired according to the wall clock.
    ///
    /// Normal operation of ConnectionOutcomes works on [`Instant`], which has nice properties such
    /// as monotonicity and immunity to manual system time adjustments. However, `Instant` does not
    /// track time when the system is suspended, and as such we might have a `LongTerm` failure that
    /// appears more recent than it actually is. This method removes any entries that would have
    /// expired assuming `Instant` was following `SystemTime`.
    ///
    /// Detection based on `SystemTime` is a heuristic, since the user may also adjust the system
    /// clock manually. But clearing when it would be better not to is equivalent to restarting the
    /// app, and *not* clearing can always be *fixed* by restarting the app.
    pub fn reset_if_system_has_probably_been_asleep(&mut self, now: SystemTime) {
        let Self {
            params,
            recent_failures,
        } = self;
        let Some(cutoff) = now.checked_sub(params.long_term_age_cutoff) else {
            // Give up with too long a cutoff.
            return;
        };
        recent_failures.retain(|_route, record| cutoff < record.wall_clock);
    }
}

impl ConnectionFailureRecord {
    fn new(outcome: UnsuccessfulOutcome, started: Instant, wall_clock: SystemTime) -> Self {
        Self {
            outcome,
            started,
            wall_clock,
            failure_count: 1,
        }
    }

    fn update(
        &mut self,
        new_outcome: UnsuccessfulOutcome,
        new_started: Instant,
        new_wall_clock: SystemTime,
        max_count: u8,
    ) {
        let Self {
            outcome,
            started,
            wall_clock,
            failure_count,
        } = self;
        *outcome = outcome.merge(new_outcome);
        *started = new_started;
        *wall_clock = new_wall_clock;
        *failure_count = (*failure_count + 1).min(max_count)
    }
}

impl UnsuccessfulOutcome {
    fn merge(self, other: UnsuccessfulOutcome) -> UnsuccessfulOutcome {
        match (self, other) {
            (Self::LongTerm, _) | (_, Self::LongTerm) => Self::LongTerm,
            (Self::ShortTerm, Self::ShortTerm) => Self::ShortTerm,
        }
    }
}

impl<P: RouteDelayPolicy<R>, R> RouteDelayPolicy<R> for &mut P {
    fn compute_delay(&self, route: &R, now: Instant) -> Duration {
        P::compute_delay(self, route, now)
    }
    fn wants_recalculation(&mut self) -> impl Future<Output = ()> + '_ {
        P::wants_recalculation(self)
    }
}

/// Delay routes according to previous history, with some caps.
///
/// Delay routes according to the following rules:
/// - older failures cause less delay
/// - more consecutive failures cause more delay
/// - delay should increase exponentially with failure count
/// - absent any information there should be no delay
impl<R: Hash + Eq> RouteDelayPolicy<R> for ConnectionOutcomes<R> {
    fn compute_delay(&self, route: &R, now: Instant) -> Duration {
        let Self {
            recent_failures,
            params,
        } = self;

        let Some(ConnectionFailureRecord {
            outcome,
            started,
            wall_clock: _,
            failure_count,
        }) = recent_failures.get(route)
        else {
            return Duration::ZERO;
        };

        params.compute_delay(
            *outcome,
            now.saturating_duration_since(*started),
            *failure_count,
        )
    }
}

impl ConnectionOutcomeParams {
    /// Compute the delay given the time since the last failure and count of
    /// repeated failures.
    ///
    /// The implementation is based on exponential backoff with a scaling factor
    /// based on the amount of time since the last known failure.
    pub fn compute_delay(
        &self,
        unsuccessful_outcome: UnsuccessfulOutcome,
        since_last_failure: Duration,
        consecutive_failure_count: u8,
    ) -> Duration {
        let Self {
            short_term_age_cutoff,
            long_term_age_cutoff,
            cooldown_growth_factor,
            count_growth_factor,
            max_count,
            max_delay,
        } = *self;

        let age_cutoff = match unsuccessful_outcome {
            UnsuccessfulOutcome::ShortTerm => short_term_age_cutoff,
            UnsuccessfulOutcome::LongTerm => long_term_age_cutoff,
        };

        // Exponential backoff: as the count grows, the delay should be longer.
        //
        // This is equivalent to "normal exponential backoff" with a change of
        // constants. The usual formula is
        //
        //    t = min(T * (C**x - 1), D)
        //
        // where `x` is the number of failures, `C` is the exponential growth
        // constant, `T` is a time constant, and `D` is the maximum delay.
        //
        // We let `M` be the value of `x` past which the clamp applies, so
        // `D = T * (C**M - 1)`, and apply associativity of `min` to get
        //
        //    t = T * C**min(x, M) - 1
        //
        // We introduce a new constant `k` and substitute `C = k**(1/M)`:
        //
        //    t = T * k**( min(x, M) / M) - 1
        //
        // Then divide both sides by our original `D` to get the delay as a
        // fraction of the maximum value:
        //
        //    t/D = [ k ** ( min(x, M) / M) - 1 ] / [ k - 1]
        //
        // The right side is exactly the formula below, where `M` is the maximum
        // count and `k` is the growth factor. The upside of this formulation is
        // that it lets us specify the count value `M` at which the maximum
        // duration is achieved as an input instead of as a function of `T`,
        // `C`, and `D`.
        let count_factor = {
            let normalized_count =
                consecutive_failure_count.min(max_count) as f32 / max_count as f32;

            let numerator = count_growth_factor.powf(normalized_count) - 1.0;
            let denominator = count_growth_factor - 1.0;
            numerator / denominator
        };

        // Exponential decrease: as the age of the last failure increases, it
        // becomes less relevant and the delay is shorter.
        let age_factor = {
            let normalized_age = since_last_failure.div_duration_f32(age_cutoff).min(1.0);
            let numerator = cooldown_growth_factor - cooldown_growth_factor.powf(normalized_age);
            let denominator = cooldown_growth_factor - 1.0;
            numerator / denominator
        };

        // Combine the two factors so that if either one is zero, the whole
        // thing is zero.
        let factor = age_factor * count_factor;

        // Clamp the product as insurance since `Duration::mul_f32` panics if
        // the input is negative, and in case of rounding errors that would make
        // it > 1.
        max_delay.mul_f32(factor.clamp(0.0, 1.0))
    }
}

/// A [`RouteDelayPolicy`] that acts on a route's [transport part](UsesTransport), ignoring the rest
/// of it.
pub struct DelayBasedOnTransport<T>(pub T);

impl<T, R: UsesTransport> RouteDelayPolicy<R> for DelayBasedOnTransport<T>
where
    T: RouteDelayPolicy<TransportRoute>,
{
    fn compute_delay(&self, route: &R, now: Instant) -> Duration {
        self.0.compute_delay(route.transport_part(), now)
    }
    fn wants_recalculation(&mut self) -> impl Future<Output = ()> + '_ {
        self.0.wants_recalculation()
    }
}

/// A wrapper around [`ConnectionOutcomes`] that turns into [`NoDelay`](super::NoDelay) on a
/// [`NetworkChangeEvent`].
pub struct ResettingConnectionOutcomes<R> {
    outcomes: Option<ConnectionOutcomes<R>>,
    reset_signal: NetworkChangeEvent,
}

impl<R> ResettingConnectionOutcomes<R> {
    pub fn new(outcomes: ConnectionOutcomes<R>, reset_signal: &NetworkChangeEvent) -> Self {
        Self {
            outcomes: Some(outcomes),
            reset_signal: reset_signal.clone(),
        }
    }
}

impl<R: Eq + Hash> RouteDelayPolicy<R> for ResettingConnectionOutcomes<R> {
    fn compute_delay(&self, route: &R, now: Instant) -> Duration {
        let Some(outcomes) = &self.outcomes else {
            return Duration::ZERO;
        };
        outcomes.compute_delay(route, now)
    }

    async fn wants_recalculation(&mut self) {
        if self.outcomes.is_none() {
            // We only report that we want recalculation if anything would change.
            () = std::future::pending().await;
        }
        match self.reset_signal.changed().await {
            Ok(()) => {}
            Err(_) => {
                // If the sender for the reset signal dropped, we'll never want recalculation.
                () = std::future::pending().await;
            }
        }
        self.outcomes = None;
    }
}

#[derive(Copy, Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct IndividualRouteKey {
    time: Instant,
    original_group_index: usize,
    resolved_index: usize,
}

/// [`Stream`] that maps elements `(a, b)` in the wrapped stream to `(b, a)`.
#[pin_project]
#[derive(Clone, Debug)]
struct SwapPairStream<S>(#[pin] S);

impl<S: Stream<Item = (A, B)>, A, B> Stream for SwapPairStream<S> {
    type Item = (B, A);

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.project()
            .0
            .poll_next(cx)
            .map(|v| v.map(|(a, b)| (b, a)))
    }
}

impl<S: FusedStream<Item = (A, B)>, A, B> FusedStream for SwapPairStream<S> {
    fn is_terminated(&self) -> bool {
        self.0.is_terminated()
    }
}

#[cfg_attr(feature = "test-util", visibility::make(pub))]
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(300);

/// A group of resolved routes that came from the same unresolved route.
#[derive(Clone, Debug, derive_more::IntoIterator)]
pub struct ResolvedRoutes<R> {
    routes: Vec<R>,
}

/// Produces a single `(ResolvedRoutes<R>, ResolveMeta)` pair.
///
/// Assumes that the provided routes came from the same pre-resolution source.
pub(crate) fn as_resolved_group<R>(routes: Vec<R>) -> (ResolvedRoutes<R>, ResolveMeta) {
    let routes = ResolvedRoutes { routes };
    let meta = ResolveMeta {
        original_group_index: 0,
    };
    (routes, meta)
}

type EagerResolutionResult<R> = Result<ResolvedRoutes<R>, (Arc<str>, DnsError)>;

/// Produces a stream of resolved routes.
///
/// Resolves all the input routes in parallel.
fn eagerly_resolve_each<'r, R: ResolveHostnames + Clone + 'static>(
    routes: impl Iterator<Item = R> + 'r,
    resolver: &'r impl Resolver,
) -> impl FusedStream<Item = (EagerResolutionResult<R::Resolved>, ResolveMeta)> + 'r {
    FuturesUnordered::from_iter(routes.enumerate().map(|(index, route)| async move {
        let resolution = super::resolve_route(resolver, route)
            .await
            .map(|routes| ResolvedRoutes {
                routes: routes.collect(),
            });

        (
            resolution,
            ResolveMeta {
                original_group_index: index,
            },
        )
    }))
}

/// A [`Stream`] that sorts the input as much as possible.
///
/// Wraps the input `Stream` in a stream that eagerly pulls key-value pairs from
/// the input when polled and attempts to emit them in order by key. If the pair
/// with the next key in the sequence is not available, waits up to the
/// configured debounce duration before yielding the pair with the smallest
/// available key.
#[derive_where(Debug; S: Debug, V: Debug, K: Ord + Clone + Debug)]
#[pin_project(project=TryPickMinProj)]
struct MinKeyValueQueueStream<S, K, V> {
    #[pin]
    input: S,
    #[pin]
    debounce_sleep: tokio::time::Sleep,

    heap: MinKeyValueQueue<K, V>,
    debounce_time: Duration,
    debouncing: bool,
    missing_keys: RangeSet<K>,
}

trait SequentialKey: Ord + Copy {
    const MIN: Self;
    const MAX: Self;
    fn seq_next(&self) -> Self;
}

impl SequentialKey for usize {
    const MIN: Self = usize::MIN;
    const MAX: Self = usize::MAX;
    fn seq_next(&self) -> Self {
        self + 1
    }
}

impl SequentialKey for ResolveMeta {
    const MIN: Self = ResolveMeta {
        original_group_index: SequentialKey::MIN,
    };
    const MAX: Self = ResolveMeta {
        original_group_index: SequentialKey::MAX,
    };
    fn seq_next(&self) -> Self {
        Self {
            original_group_index: self.original_group_index.seq_next(),
        }
    }
}

impl<S: FusedStream<Item = (K, V)>, K: SequentialKey, V> MinKeyValueQueueStream<S, K, V> {
    fn new(input: S, debounce_time: Duration) -> Self {
        Self {
            input,
            heap: Default::default(),
            debounce_time,
            debounce_sleep: tokio::time::sleep(Duration::ZERO),
            debouncing: false,
            missing_keys: RangeSet::from([K::MIN..K::MAX]),
        }
    }
}

impl<S: FusedStream<Item = (K, V)>, K: SequentialKey, V> Stream
    for MinKeyValueQueueStream<S, K, V>
{
    type Item = S::Item;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        let TryPickMinProj {
            mut input,
            heap,
            mut debounce_sleep,
            debounce_time,
            debouncing,
            missing_keys,
        } = self.as_mut().project();
        if input.is_terminated() {
            return std::task::Poll::Ready(heap.pop());
        }

        while let std::task::Poll::Ready(item) = input.as_mut().poll_next(cx) {
            match item {
                Some(item) => {
                    heap.push(item);
                }
                None => {
                    // There are no more pending items, so just return from
                    // the queue.
                    return std::task::Poll::Ready(heap.pop());
                }
            }
        }

        // If execution has reached this point, the input stream is not
        // terminated and all the results of already-finished pending futures
        // are in the queue.

        let Some((key, _)) = heap.peek() else {
            // Nothing to do but wait for the next item from the stream.
            return std::task::Poll::Pending;
        };

        if missing_keys
            .first()
            .is_some_and(|smallest| key <= &smallest.start)
        {
            // There might have been a debounce in progress before some elements
            // got added to the queue. Cancel that if so.
            *debouncing = false;

            missing_keys.remove((*key)..key.seq_next());
            return std::task::Poll::Ready(heap.pop());
        }

        // The first item in the heap is not the next one in order. If we're
        // not debouncing, we should start.
        if !*debouncing {
            *debouncing = true;
            debounce_sleep
                .as_mut()
                .reset(Instant::now() + *debounce_time);
        }

        match debounce_sleep.as_mut().poll(cx) {
            std::task::Poll::Ready(()) => {
                *debouncing = false;
                missing_keys.remove((*key)..key.seq_next());
                std::task::Poll::Ready(heap.pop())
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

impl<S: FusedStream<Item = (K, V)>, K: SequentialKey, V> FusedStream
    for MinKeyValueQueueStream<S, K, V>
{
    fn is_terminated(&self) -> bool {
        let Self { input, heap, .. } = self;
        input.is_terminated() && heap.is_empty()
    }
}

#[cfg(test)]
mod test {
    use std::collections::{HashMap, HashSet};
    use std::net::{IpAddr, Ipv4Addr};

    use assert_matches::assert_matches;
    use const_str::ip_addr;
    use futures_util::FutureExt as _;
    use itertools::Itertools as _;
    use proptest::proptest;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::UnboundedReceiverStream;

    use super::*;
    use crate::dns::lookup_result::LookupResult;
    use crate::route::testutils::FakeRoute;
    use crate::route::{NoDelay, UnresolvedHost};

    impl<S, R, SP> Schedule<S, R, SP>
    where
        S: FusedStream<Item = (ResolvedRoutes<R>, ResolveMeta)>,
        SP: RouteDelayPolicy<R>,
    {
        pub fn as_stream(self: Pin<&mut Self>) -> impl Stream<Item = R> + use<'_, S, R, SP> {
            let schedule = self;
            futures_util::stream::unfold(schedule, |mut schedule| async {
                schedule.as_mut().next().await.map(|r| (r, schedule))
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn single_resolved_route_e2e() {
        let resolver = RouteResolver { allow_ipv6: true };
        let name_resolver = HashMap::from([(
            "domain-name",
            LookupResult {
                ipv4: vec![ip_addr!(v4, "192.0.2.1")],
                ipv6: vec![ip_addr!(v6, "3fff::1234")],
            },
        )]);

        let unresolved_routes = [FakeRoute(UnresolvedHost("domain-name".into()))];

        let resolve = resolver.resolve(unresolved_routes.into_iter(), &name_resolver);
        let schedule = Schedule::new(resolve.fuse(), NoDelay, Duration::ZERO);

        let start_at = Instant::now();
        let schedule = std::pin::pin!(schedule);
        let schedule: Vec<_> = schedule
            .as_stream()
            .map(|r| (r, Instant::now().duration_since(start_at)))
            .collect()
            .await;

        assert_eq!(
            schedule,
            vec![
                (FakeRoute(ip_addr!("3fff::1234")), Duration::ZERO),
                (FakeRoute(ip_addr!("192.0.2.1")), HAPPY_EYEBALLS_DELAY),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn multiple_resolved_routes_e2e() {
        let resolver = RouteResolver { allow_ipv6: true };

        let name_resolver = HashMap::from([
            (
                "name-1",
                LookupResult {
                    ipv4: vec![ip_addr!(v4, "192.0.2.11")],
                    ipv6: vec![ip_addr!(v6, "3fff::1234")],
                },
            ),
            (
                "name-2",
                LookupResult {
                    ipv4: vec![ip_addr!(v4, "192.0.2.22")],
                    ipv6: vec![ip_addr!(v6, "3fff::5678")],
                },
            ),
        ]);

        let unresolved_routes = [
            FakeRoute(UnresolvedHost("name-1".into())),
            FakeRoute(UnresolvedHost("name-2".into())),
        ];

        let resolve = resolver.resolve(unresolved_routes.into_iter(), &name_resolver);
        let schedule = Schedule::new(
            futures_util::StreamExt::fuse(resolve),
            NoDelay,
            Duration::ZERO,
        );

        let start_at = Instant::now();
        let schedule = std::pin::pin!(schedule);
        let schedule: Vec<_> = schedule
            .as_stream()
            .map(|r| (r, Instant::now().duration_since(start_at)))
            .collect()
            .await;

        // Compare with HashSet since the ordering isn't deterministic because
        // the DNS resolution is instantaneous.
        assert_eq!(
            HashSet::from_iter(schedule),
            HashSet::from([
                (FakeRoute(ip_addr!("3fff::1234")), Duration::ZERO),
                (FakeRoute(ip_addr!("192.0.2.11")), HAPPY_EYEBALLS_DELAY),
                (FakeRoute(ip_addr!("3fff::5678")), Duration::ZERO),
                (FakeRoute(ip_addr!("192.0.2.22")), HAPPY_EYEBALLS_DELAY),
            ])
        );
    }

    macro_rules! assert_in_range {
        ($v:expr, $range:expr) => {
            let v = $v;
            let range = $range;
            assert!(range.contains(&v), "{v:?} not in {range:?}");
        };
    }

    proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig { cases: 99, .. Default::default() })]

        #[test]
        fn connection_outcome_delay_bounds(cooldown_growth_factor in 1.1f32..100.0, count_growth_factor in 1.1f32..100.0) {
            const MAX_DELAY: Duration = Duration::from_secs(10);
            const AGE_CUTOFF: Duration = Duration::from_secs(100);
            const COUNT_CUTOFF: u8 = 5;

            let params = ConnectionOutcomeParams {
                short_term_age_cutoff: AGE_CUTOFF,
                long_term_age_cutoff: AGE_CUTOFF,
                cooldown_growth_factor,
                count_growth_factor,
                max_count: COUNT_CUTOFF,
                max_delay: MAX_DELAY,
            };

            // Lots of failures, the last one recent.
            assert_eq!(
                params.compute_delay(UnsuccessfulOutcome::ShortTerm, Duration::ZERO, COUNT_CUTOFF),
                MAX_DELAY
            );

            proptest!(|(count in 0..COUNT_CUTOFF)|{
                // Regardless of the count, the delay is zero if the information is
                // too old.
                assert_eq!(
                    params.compute_delay(UnsuccessfulOutcome::ShortTerm, AGE_CUTOFF, count),
                    Duration::ZERO
                );
            });

            proptest!(|(count in 0..COUNT_CUTOFF, age_seconds in 0..AGE_CUTOFF.as_secs())| {
                let delay = params.compute_delay(
                    UnsuccessfulOutcome::ShortTerm,
                    Duration::from_secs(age_seconds),
                    count
                );
                // The delay should always be less than the configured max.
                assert_in_range!(delay, Duration::ZERO..MAX_DELAY);
            });
        }
    }

    impl<R: Hash + Eq + Clone> ConnectionOutcomes<R> {
        fn record_outcome(
            &mut self,
            route: R,
            started: Instant,
            connect_duration: Duration,
            result: Result<(), UnsuccessfulOutcome>,
        ) {
            self.apply_outcome_updates(
                [(route, AttemptOutcome { started, result })],
                started + connect_duration,
                SystemTime::now(),
            )
        }
    }

    #[test]
    fn connection_outcomes_delays_failing_route() {
        const MAX_DELAY: Duration = Duration::from_secs(100);
        const AGE_CUTOFF: Duration = Duration::from_secs(1000);

        const MAX_COUNT: u8 = 5;
        let mut outcomes = ConnectionOutcomes::new(ConnectionOutcomeParams {
            short_term_age_cutoff: AGE_CUTOFF,
            long_term_age_cutoff: AGE_CUTOFF,
            cooldown_growth_factor: 2.0,
            count_growth_factor: 10.0,
            max_count: MAX_COUNT,
            max_delay: MAX_DELAY,
        });

        const ROUTE: &str = "route";
        let start = Instant::now();

        // Without any information, the delay should be zero.
        assert_eq!(outcomes.compute_delay(&ROUTE, start), Duration::ZERO);

        let mut delays = vec![];
        let mut now = start;
        for _ in 0..=MAX_COUNT {
            const CONNECT_DELAY: Duration = Duration::from_secs(10);
            // Record that the previous connection attempt failed after CONNECT_DELAY.
            outcomes.record_outcome(
                ROUTE,
                now,
                CONNECT_DELAY,
                Err(UnsuccessfulOutcome::default()),
            );
            now += CONNECT_DELAY;

            // Compute the new delay and "wait" for it to elapse before the next
            // connection attempt.
            let delay = outcomes.compute_delay(&ROUTE, now);
            delays.push(delay);
            now += delay;
        }

        assert_eq!(
            delays.iter().map(Duration::as_secs).collect_vec(),
            [6, 16, 32, 58, 99, 99]
        );
    }

    #[test]
    fn connection_outcomes_reset_by_cutoff() {
        const MAX_DELAY: Duration = Duration::from_secs(100);
        const AGE_CUTOFF: Duration = Duration::from_secs(1000);
        const MAX_COUNT: u8 = 5;

        let mut outcomes = ConnectionOutcomes::new(ConnectionOutcomeParams {
            short_term_age_cutoff: AGE_CUTOFF,
            long_term_age_cutoff: AGE_CUTOFF,
            cooldown_growth_factor: 2.0,
            count_growth_factor: 10.0,
            max_count: MAX_COUNT,
            max_delay: MAX_DELAY,
        });

        const ROUTE: &str = "route";
        let start = Instant::now();

        // Without any information, the delay should be zero.
        assert_eq!(outcomes.compute_delay(&ROUTE, start), Duration::ZERO);

        const CONNECT_DELAY: Duration = Duration::from_secs(10);
        // Record some failures.
        outcomes.record_outcome(
            ROUTE,
            start,
            CONNECT_DELAY,
            Err(UnsuccessfulOutcome::default()),
        );
        outcomes.record_outcome(
            ROUTE,
            start + CONNECT_DELAY,
            CONNECT_DELAY,
            Err(UnsuccessfulOutcome::default()),
        );
        outcomes.record_outcome(
            ROUTE,
            start + 2 * CONNECT_DELAY,
            CONNECT_DELAY,
            Err(UnsuccessfulOutcome::default()),
        );

        let full_delay = outcomes.compute_delay(&ROUTE, start + 3 * CONNECT_DELAY);
        assert_ne!(full_delay, Duration::ZERO, "shouldn't decay that quickly");

        outcomes.reset(start + CONNECT_DELAY);
        let same_delay = outcomes.compute_delay(&ROUTE, start + 3 * CONNECT_DELAY);
        assert_eq!(same_delay, full_delay, "should keep more recent outcome");

        outcomes.reset(start + 3 * CONNECT_DELAY);
        let reset_delay = outcomes.compute_delay(&ROUTE, start + 3 * CONNECT_DELAY);
        assert_eq!(reset_delay, Duration::ZERO, "all outcomes reset");
    }

    #[test]
    fn connection_outcomes_delays_decrease_over_time() {
        const MAX_DELAY: Duration = Duration::from_secs(100);
        const AGE_CUTOFF: Duration = Duration::from_secs(1000);
        const MAX_COUNT: u8 = 5;

        let mut outcomes = ConnectionOutcomes::new(ConnectionOutcomeParams {
            short_term_age_cutoff: AGE_CUTOFF,
            long_term_age_cutoff: AGE_CUTOFF,
            cooldown_growth_factor: 2.0,
            count_growth_factor: 10.0,
            max_count: MAX_COUNT,
            max_delay: MAX_DELAY,
        });

        const ROUTE: &str = "route";
        let start = Instant::now();
        outcomes.record_outcome(
            ROUTE,
            start,
            Duration::ZERO,
            Err(UnsuccessfulOutcome::default()),
        );

        let delays = (0..=5)
            .map(|i| {
                let when = start + Duration::from_secs(i * 200);
                outcomes.compute_delay(&ROUTE, when)
            })
            .collect_vec();

        assert_eq!(
            delays.iter().map(Duration::as_secs).collect_vec(),
            [6, 5, 4, 3, 1, 0]
        );
    }

    #[test]
    fn connection_outcomes_delays_distinguish_short_and_long_term() {
        const MAX_DELAY: Duration = Duration::from_secs(100);
        const AGE_CUTOFF: Duration = Duration::from_secs(1000);
        const MAX_COUNT: u8 = 5;

        let mut outcomes = ConnectionOutcomes::new(ConnectionOutcomeParams {
            short_term_age_cutoff: Duration::ZERO,
            long_term_age_cutoff: AGE_CUTOFF,
            cooldown_growth_factor: 2.0,
            count_growth_factor: 10.0,
            max_count: MAX_COUNT,
            max_delay: MAX_DELAY,
        });

        const SHORT_TERM: &str = "short-term";
        const LONG_TERM: &str = "long-term";
        let start = Instant::now();
        outcomes.record_outcome(
            SHORT_TERM,
            start,
            Duration::ZERO,
            Err(UnsuccessfulOutcome::ShortTerm),
        );
        outcomes.record_outcome(
            LONG_TERM,
            start,
            Duration::ZERO,
            Err(UnsuccessfulOutcome::LongTerm),
        );

        let delays = (0..=5)
            .map(|i| {
                let when = start + Duration::from_secs(i * 200);
                (
                    outcomes.compute_delay(&SHORT_TERM, when),
                    outcomes.compute_delay(&LONG_TERM, when),
                )
            })
            .collect_vec();

        assert_eq!(
            delays
                .iter()
                .map(|(a, b)| (Duration::as_secs(a), Duration::as_secs(b)))
                .collect_vec(),
            [(0, 6), (0, 5), (0, 4), (0, 3), (0, 1), (0, 0)]
        );
    }

    #[test]
    fn connection_outcomes_prefers_long_term() {
        const MAX_DELAY: Duration = Duration::from_secs(100);
        const AGE_CUTOFF: Duration = Duration::from_secs(1000);
        const MAX_COUNT: u8 = 5;

        let mut outcomes = ConnectionOutcomes::new(ConnectionOutcomeParams {
            // If we set this to zero, the short-then-long case gets GC'd immediately.
            short_term_age_cutoff: Duration::from_millis(1),
            long_term_age_cutoff: AGE_CUTOFF,
            cooldown_growth_factor: 2.0,
            count_growth_factor: 10.0,
            max_count: MAX_COUNT,
            max_delay: MAX_DELAY,
        });

        const SHORT_THEN_LONG: &str = "short-long";
        const LONG_THEN_SHORT: &str = "long-short";
        let start = Instant::now();
        outcomes.record_outcome(
            SHORT_THEN_LONG,
            start,
            Duration::ZERO,
            Err(UnsuccessfulOutcome::ShortTerm),
        );
        outcomes.record_outcome(
            SHORT_THEN_LONG,
            start,
            Duration::ZERO,
            Err(UnsuccessfulOutcome::LongTerm),
        );
        outcomes.record_outcome(
            LONG_THEN_SHORT,
            start,
            Duration::ZERO,
            Err(UnsuccessfulOutcome::LongTerm),
        );
        outcomes.record_outcome(
            LONG_THEN_SHORT,
            start,
            Duration::ZERO,
            Err(UnsuccessfulOutcome::ShortTerm),
        );

        let delays = (0..=5)
            .map(|i| {
                let when = start + Duration::from_secs(i * 200);
                (
                    outcomes.compute_delay(&SHORT_THEN_LONG, when),
                    outcomes.compute_delay(&LONG_THEN_SHORT, when),
                )
            })
            .collect_vec();

        assert_eq!(
            delays
                .iter()
                .map(|(a, b)| (Duration::as_secs(a), Duration::as_secs(b)))
                .collect_vec(),
            [(16, 16), (14, 14), (11, 11), (8, 8), (4, 4), (0, 0)]
        );
    }

    #[test]
    fn connection_outcomes_resets_after_sleep() {
        const MAX_DELAY: Duration = Duration::from_secs(100);
        const AGE_CUTOFF: Duration = Duration::from_secs(1000);
        const MAX_COUNT: u8 = 5;

        let mut outcomes = ConnectionOutcomes::new(ConnectionOutcomeParams {
            short_term_age_cutoff: AGE_CUTOFF,
            long_term_age_cutoff: AGE_CUTOFF,
            cooldown_growth_factor: 2.0,
            count_growth_factor: 10.0,
            max_count: MAX_COUNT,
            max_delay: MAX_DELAY,
        });

        const ROUTE: &str = "route";
        let start = Instant::now();
        let wall_clock_start = SystemTime::now();
        outcomes.apply_outcome_updates(
            [(
                ROUTE,
                AttemptOutcome {
                    started: start,
                    result: Err(UnsuccessfulOutcome::default()),
                },
            )],
            start,
            wall_clock_start,
        );

        assert_eq!(outcomes.compute_delay(&ROUTE, start).as_secs(), 6);

        outcomes.reset_if_system_has_probably_been_asleep(wall_clock_start + AGE_CUTOFF / 2);
        assert_eq!(outcomes.compute_delay(&ROUTE, start).as_secs(), 6);

        outcomes.reset_if_system_has_probably_been_asleep(wall_clock_start + AGE_CUTOFF);
        assert_eq!(outcomes.compute_delay(&ROUTE, start).as_secs(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn min_kvq_stream_debounce() {
        use std::task::Poll;

        use futures_util::poll;

        let (source_tx, source_rx) = tokio::sync::mpsc::unbounded_channel();
        const DEBOUNCE: Duration = Duration::from_secs(1);
        let stream =
            MinKeyValueQueueStream::new(UnboundedReceiverStream::new(source_rx).fuse(), DEBOUNCE);
        let mut stream = std::pin::pin!(stream);

        // Poll with no items.
        assert_matches!(poll!(stream.as_mut().next()), Poll::Pending);

        // Does not wait to return the next item.
        let _ = source_tx.send((0, 'a'));
        let _ = source_tx.send((5, 'f'));
        assert_matches!(poll!(stream.as_mut().next()), Poll::Ready(Some((0, 'a'))));

        // Does not skip a key immediately.
        assert_matches!(poll!(stream.as_mut().next()), Poll::Pending);

        // But if you wait long enough, it will happen.
        let start = Instant::now();
        assert_matches!(stream.as_mut().next().await, Some((5, 'f')));
        assert_eq!(start.elapsed(), DEBOUNCE);

        let _ = source_tx.send((1, 'b'));
        let _ = source_tx.send((3, 'd'));
        let _ = source_tx.send((9, 'j'));

        // If the next in-order element arrives, it will be returned immediately.
        assert_matches!(poll!(stream.as_mut().next()), Poll::Ready(Some((1, 'b'))));

        // Interrupting a debounce and then resuming won't reset the debounce timeout.
        let start = Instant::now();
        assert_matches!(
            tokio::time::timeout(DEBOUNCE / 2, stream.as_mut().next()).await,
            Err(_timeout)
        );
        assert_matches!(stream.as_mut().next().await, Some((3, 'd')));
        assert_eq!(start.elapsed(), DEBOUNCE);

        // If the next element arrives during a debounce period, it will be
        // returned immediately.
        let start = Instant::now();
        let mut stream_mut = stream.as_mut();
        tokio::join!(stream_mut.next(), async {
            tokio::time::sleep(DEBOUNCE / 2).await;
            let _ = source_tx.send((2, 'c'));
        });
        assert_eq!(start.elapsed(), DEBOUNCE / 2);
        // Then the debounce period will be restarted.
        let start = Instant::now();
        assert_matches!(stream.as_mut().next().await, Some((9, 'j')));
        assert_eq!(start.elapsed(), DEBOUNCE);

        // If the next in-order elements arrive, they will be returned immediately.
        let _ = source_tx.send((4, 'e'));
        let _ = source_tx.send((6, 'g'));
        assert_matches!(poll!(stream.as_mut().next()), Poll::Ready(Some((4, 'e'))));
        assert_matches!(poll!(stream.as_mut().next()), Poll::Ready(Some((6, 'g'))));

        // If elements arrive out of order, they will be sorted during the next poll.
        let _ = source_tx.send((8, 'i'));
        let _ = source_tx.send((7, 'h'));
        drop(source_tx);

        assert_matches!(poll!(stream.as_mut().next()), Poll::Ready(Some((7, 'h'))));
        assert_matches!(poll!(stream.as_mut().next()), Poll::Ready(Some((8, 'i'))));
        assert!(stream.is_terminated());
        assert_matches!(poll!(stream.as_mut().next()), Poll::Ready(None));
    }

    #[tokio::test(start_paused = true)]
    async fn schedule_waits_for_first() {
        const DEBOUNCE_TIME: Duration = Duration::from_secs(1);
        let (resolver_stream_tx, resolver_stream_rx) = mpsc::unbounded_channel();

        let resolver_stream = UnboundedReceiverStream::new(resolver_stream_rx);
        let delay_policy = NoDelay;

        let schedule = Schedule::new(resolver_stream.fuse(), delay_policy, DEBOUNCE_TIME);
        let schedule = std::pin::pin!(schedule);

        let next = schedule.next();
        let mut next = std::pin::pin!(next);

        // With no inputs, polling won't complete.
        assert_matches!(next.as_mut().now_or_never(), None);

        // until we send the first input
        resolver_stream_tx
            .send((
                ResolvedRoutes {
                    routes: vec![FakeRoute(ip_addr!("192.0.2.1"))],
                },
                ResolveMeta {
                    original_group_index: 0,
                },
            ))
            .unwrap();

        assert_matches!(next.now_or_never(), Some(Some(FakeRoute(IpAddr::V4(_)))));
    }

    #[tokio::test(start_paused = true)]
    async fn schedule_respects_order_of_routes_in_groups() {
        const DEBOUNCE_TIME: Duration = Duration::from_secs(1);

        const ROUTE_GROUP_COUNT: u8 = 3;
        const ADDRS_PER_ROUTE: u8 = 2;

        let delay_policy = NoDelay;
        let resolver_stream = futures_util::stream::iter((0..ROUTE_GROUP_COUNT).map(|i| {
            let routes = (10..(10 + ADDRS_PER_ROUTE))
                .map(|x| FakeRoute(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10 * i + x))))
                .collect();
            (
                ResolvedRoutes { routes },
                ResolveMeta {
                    original_group_index: i.into(),
                },
            )
        }));

        let schedule = Schedule::new(resolver_stream.fuse(), delay_policy, DEBOUNCE_TIME);
        let schedule = std::pin::pin!(schedule);
        let schedule = schedule.as_stream();
        let mut schedule = std::pin::pin!(schedule);

        // This schedule has all its inputs ready immediately and won't delay
        // the first route in each group, so they should be ready immediately.
        let immediate_route_schedule: Vec<_> =
            std::iter::from_fn(|| schedule.next().now_or_never().flatten()).collect_vec();

        assert_eq!(
            immediate_route_schedule,
            [
                FakeRoute(ip_addr!("192.0.2.10")),
                FakeRoute(ip_addr!("192.0.2.20")),
                FakeRoute(ip_addr!("192.0.2.30")),
            ]
        );

        // If we wait for a small bit we will see the second wave of routes.
        let start = Instant::now();
        let remaining_route_schedule: Vec<_> = schedule.collect().await;
        assert_eq!(start.elapsed(), HAPPY_EYEBALLS_DELAY);

        assert_eq!(
            remaining_route_schedule,
            vec![
                FakeRoute(ip_addr!("192.0.2.11")),
                FakeRoute(ip_addr!("192.0.2.21")),
                FakeRoute(ip_addr!("192.0.2.31")),
            ]
        );
    }
}
