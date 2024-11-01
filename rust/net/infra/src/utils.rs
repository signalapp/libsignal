//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use base64::prelude::{Engine as _, BASE64_STANDARD};
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use http::HeaderValue;

pub(crate) mod binary_heap;

/// Constructs the value of the `Authorization` header for the `Basic` auth scheme.
pub fn basic_authorization(username: &str, password: &str) -> HeaderValue {
    let auth = BASE64_STANDARD.encode(format!("{}:{}", username, password).as_bytes());
    let auth = format!("Basic {}", auth);
    HeaderValue::try_from(auth).expect("valid header value")
}

/// Requires a `Future` to complete before the specified duration has elapsed.
///
/// Takes in a future whose return type is `Result<T, E>`, a `duration` timeout,
/// and a `timeout_error` of type `E`. Internally, a [tokio::time::timeout] is called,
/// but the return type of this method is the same as the return type of the given `future`,
/// i.e. `Result<T, E>`, which in the case of timing out will be `Err(timeout_error)`.
pub async fn timeout<T, E, F>(duration: Duration, timeout_error: E, future: F) -> Result<T, E>
where
    F: Future<Output = Result<T, E>>,
{
    match tokio::time::timeout(duration, future).await {
        Ok(r) => r,
        Err(_) => Err(timeout_error),
    }
}

/// Takes a series of `Future` objects that all return a `Result<T, E>`
/// and returns when the first of them completes successfully.
///
/// Errors from the failed futures are deliberately ignored by this helper method.
/// If error processing is needed, the caller should pass futures that inspect their errors.
pub async fn first_ok<T, E, F, I>(futures: I) -> Option<T>
where
    F: Future<Output = Result<T, E>>,
    I: IntoIterator<Item = F>,
{
    FuturesUnordered::from_iter(futures)
        .filter_map(|result| future::ready(result.ok()))
        .next()
        .await
}

/// Represents an event that can fire on any thread and synchronously runs callbacks when it does.
///
/// The choice to run callbacks synchronously, rather than spawning tasks or providing a watchable
/// signal (see [`tokio::sync::watch`]), has a few trade-offs:
///
/// - Pro: The implementation is simpler and more lightweight.
/// - Pro: Both subscriptions and fires can happen outside of a tokio runtime. In particular, if a
///   client does not *already* have some kind of ongoing listener task, it doesn't need to add one.
/// - Con: Running the callbacks can take an arbitrary amount of time.
/// - Con: The callbacks are not run concurrently.
/// - Con: The callbacks cannot themselves include async operations.
///
/// Of course, any *particular* callback might spawn a task or send a message on a channel.
#[derive(Default)]
pub struct ObservableEvent {
    // We could make ObservableEvent Clone by putting the Condvar inside the Arc, but *not* doing so
    // lets us control who can fire the event.
    state: Arc<std::sync::Mutex<ObservableEventState>>,
    fire_in_progress_cvar: std::sync::Condvar,
}

#[derive(Default)]
struct ObservableEventState {
    actions: indexmap::IndexMap<u64, Box<dyn FnMut() + Send>>,
    fire_in_progress: bool,
    next_id: u64,
    ids_to_remove: Vec<u64>,
}

/// Represents an action subscription to an [`ObservableEvent`].
///
/// When dropped, removes the registered callback from the event's list of callbacks.
#[must_use]
#[derive(Debug)]
pub struct EventSubscription {
    event: std::sync::Weak<std::sync::Mutex<ObservableEventState>>,
    id: u64,
}

/// A backstop timeout after which an event firing is considered to have failed because a previous
/// fire is taking too long.
const STALLED_EVENT_TIMEOUT: Duration = Duration::from_secs(5);

impl ObservableEvent {
    pub fn new() -> Self {
        Self::default()
    }

    /// Fires the event, running all its callbacks **synchronously**.
    ///
    /// Subscriptions may be added during the execution of `fire` (that is,
    /// [`subscribe`](Self::subscribe) won't block waiting for `fire` to complete), but they will
    /// not be invoked unless `fire` is called again. If `fire` is called again during the execution
    /// of `fire`, the second call will block until the first one completes.
    pub fn fire(&self) {
        // Take the list of actions out of the mutex to avoid running arbitrary code while holding
        // the lock.
        let mut actions = {
            let guard = self
                .state
                .lock()
                .expect("no panics because no arbitrary code");
            let (mut guard, timeout_result) = self
                .fire_in_progress_cvar
                .wait_timeout_while(guard, STALLED_EVENT_TIMEOUT, |guard| guard.fire_in_progress)
                .expect("no panics because no arbitrary code");
            if timeout_result.timed_out() {
                drop(guard);
                log::error!(concat!(
                    "previous ObservableEvent callbacks are taking too long; ",
                    "maybe ObservableEvent isn't the right tool for the job"
                ));
                return;
            }
            guard.fire_in_progress = true;
            std::mem::take(&mut guard.actions)
        };

        for f in actions.values_mut() {
            f()
        }

        let mut guard = self
            .state
            .lock()
            .expect("no panics because no arbitrary code");
        // In the common case, both of the lists in 'guard' will currently be empty:
        // - no subscriptions were dropped during the event
        // - no new subscriptions were added during the event
        // However, both are possible and need to be handled.
        guard
            .ids_to_remove
            .retain(|id| actions.shift_remove(id).is_none());
        actions.extend(std::mem::take(&mut guard.actions));
        guard.actions = actions;
        guard.fire_in_progress = false;
        self.fire_in_progress_cvar.notify_one();
    }

    /// Adds a callback to the list that will be invoked when the event fires.
    ///
    /// Callbacks should generally be quick, since the event firer will wait for them all to execute
    /// before returning, and a second fire that comes in while callbacks are executing will not
    /// result in a second call.
    ///
    /// The callback should not assume anything about the context it will be run in. In particular,
    /// if it wants to spawn tokio tasks, it should capture a [`tokio::runtime::Handle`] rather than
    /// relying on there being a current runtime.
    ///
    /// The returned EventSubscription must be stored; dropping it will remove the callback from the
    /// list.
    pub fn subscribe(&self, callback: Box<dyn FnMut() + Send>) -> EventSubscription {
        let id = {
            let mut guard = self
                .state
                .lock()
                .expect("no panics because no arbitrary code");
            let id = guard.next_id;
            guard.next_id += 1;
            guard.actions.insert(id, callback);
            id
        };
        EventSubscription {
            event: Arc::downgrade(&self.state),
            id,
        }
    }
}

impl Drop for EventSubscription {
    fn drop(&mut self) {
        let Some(event) = self.event.upgrade() else {
            // If the event owner is gone, there's nothing to unsubscribe from.
            return;
        };
        let mut guard = event.lock().expect("no panics because no arbitrary code");
        if let Some(callback) = guard.actions.shift_remove(&self.id) {
            // Make sure we drop the lock before we drop the callback (which could run arbitrary
            // Drop impls).
            drop(guard);
            drop(callback);
        } else {
            guard.ids_to_remove.push(self.id);
        }
    }
}

/// In the tokio time paused test mode, if some logic is supposed to wake up at specific time
/// and a test wants to make sure it observes the result of that logic without moving
/// the time past that point, it's not enough to call `sleep()` or `advance()` alone.
/// The combination of sleeping and advancing by 0 makes sure that all events
/// (in all tokio threads) scheduled to run at (or before) that specific time are processed.
///
/// `sleep_and_catch_up_showcase()` test demonstrates this behavior.
#[cfg(test)]
pub(crate) async fn sleep_and_catch_up(duration: Duration) {
    tokio::time::sleep(duration).await;
    tokio::time::advance(Duration::ZERO).await
}

/// See [`sleep_and_catch_up`]
#[cfg(test)]
pub(crate) async fn sleep_until_and_catch_up(time: tokio::time::Instant) {
    tokio::time::sleep_until(time).await;
    tokio::time::advance(Duration::ZERO).await
}

// We allow dead code here just to make sure this method does not bit rot. It is
// compiled as part of the unit tests, but is only called manually by developers.
#[cfg(feature = "dev-util")]
#[allow(dead_code)]
pub(crate) fn development_only_enable_nss_standard_debug_interop(
    ssl: &mut boring_signal::ssl::SslConnectorBuilder,
) -> Result<(), crate::errors::TransportConnectError> {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::sync::Mutex;

    use once_cell::sync::OnceCell;

    use crate::errors::TransportConnectError;

    log::warn!(
        "NSS TLS debugging enabled! If you don't expect this, report to security@signal.org"
    );
    if let Ok(keylog_path) = std::env::var("SSLKEYLOGFILE") {
        // This copies the behavior from BoringSSL where the connection will fail if
        //  SSLKEYLOGFILE is set but the file cannot be created. See:
        //  https://boringssl.googlesource.com/boringssl/+/refs/heads/master/tool/client.cc#400
        static FILE_OPEN_MUTEX: OnceCell<Mutex<std::fs::File>> = OnceCell::new();

        let file_mutex = FILE_OPEN_MUTEX
            .get_or_try_init(|| {
                OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open(keylog_path)
                    .map(Mutex::new)
            })
            .map_err(|_| TransportConnectError::ClientAbort)?;

        ssl.set_keylog_callback(move |_ssl_ref, keylogfile_formatted_line| {
            let mut file = file_mutex
                .lock()
                .expect("no earlier panic while lock was held");
            let _ = writeln!(file, "{keylogfile_formatted_line}");
            let _ = file.flush();
        });
    }
    Ok(())
}

#[cfg(any(test, feature = "test-util"))]
pub mod testutil {
    use std::sync::atomic::AtomicUsize;
    use std::sync::Arc;

    /// Usable as a [Waker](std::task::Waker) for async polling.
    #[derive(Debug, Default)]
    pub struct TestWaker {
        wake_count: AtomicUsize,
    }

    impl TestWaker {
        pub fn was_woken(&self) -> bool {
            self.wake_count() != 0
        }
        pub fn wake_count(&self) -> usize {
            self.wake_count.load(std::sync::atomic::Ordering::SeqCst)
        }
        pub fn as_waker(self: &Arc<Self>) -> std::task::Waker {
            std::task::Waker::from(Arc::clone(self))
        }
    }

    impl std::task::Wake for TestWaker {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref()
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.wake_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod test {
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use assert_matches::assert_matches;
    use tokio::time;

    use super::*;
    use crate::utils::sleep_and_catch_up;

    #[tokio::test(start_paused = true)]
    async fn first_ok_picks_the_result_from_earliest_finished_future() {
        let future_1 = future(30, Ok(1));
        let future_2 = future(10, Ok(2));
        let future_3 = future(20, Ok(3));
        let result = first_ok(vec![future_1, future_2, future_3]).await.unwrap();
        assert_eq!(2, result);
    }

    #[tokio::test(start_paused = true)]
    async fn first_ok_ignores_failed_futures() {
        let future_1 = future(30, Ok(1));
        let future_2 = future(10, Err("error"));
        let future_3 = future(20, Ok(3));
        let result = first_ok(vec![future_1, future_2, future_3]).await.unwrap();
        assert_eq!(3, result);
    }

    #[tokio::test(start_paused = true)]
    async fn first_ok_returns_none_if_all_failed() {
        let future_1 = future(30, Err("error 1"));
        let future_2 = future(10, Err("error 2"));
        let future_3 = future(20, Err("error 3"));
        assert!(first_ok(vec![future_1, future_2, future_3]).await.is_none())
    }

    #[tokio::test(start_paused = true)]
    async fn sleep_and_catch_up_showcase() {
        const DURATION: Duration = Duration::from_millis(100);

        async fn test<F: Future<Output = ()>>(sleep_variant: F) -> bool {
            let flag = Arc::new(AtomicBool::new(false));
            let flag_clone = flag.clone();
            tokio::spawn(async move {
                time::sleep(DURATION).await;
                flag_clone.store(true, Ordering::Relaxed);
            });
            sleep_variant.await;
            flag.load(Ordering::Relaxed)
        }

        assert!(!test(time::sleep(DURATION)).await);
        assert!(!test(time::advance(DURATION)).await);
        assert!(test(sleep_and_catch_up(DURATION)).await);
    }

    async fn future(delay: u64, result: Result<u32, &str>) -> Result<u32, &str> {
        tokio::time::sleep(Duration::from_millis(delay)).await;
        result
    }

    #[test]
    fn observable_event() {
        let event = Arc::new(ObservableEvent::default());
        event.fire(); // Okay to call when nothing is subscribed.

        let counter = Arc::new(AtomicU32::new(0));
        let counter_for_event = counter.clone();
        let subscription = event.subscribe(Box::new(move || {
            counter_for_event.fetch_add(1, Ordering::Relaxed);
        }));

        event.fire();
        assert_eq!(1, counter.load(Ordering::Relaxed));
        event.fire();
        assert_eq!(2, counter.load(Ordering::Relaxed));

        drop(subscription);
        event.fire();
        assert_eq!(2, counter.load(Ordering::Relaxed));
    }

    #[test]
    fn observable_event_remove_preserves_order() {
        let event = Arc::new(ObservableEvent::default());

        let record = Arc::new(std::sync::Mutex::new(Vec::new()));

        let record_for_ones = record.clone();
        let _ones_subscription = event.subscribe(Box::new(move || {
            record_for_ones.lock().expect("not poisoned").push(1);
        }));

        let record_for_twos = record.clone();
        let twos_subscription = event.subscribe(Box::new(move || {
            record_for_twos.lock().expect("not poisoned").push(2);
        }));

        let record_for_threes = record.clone();
        let _threes_subscription = event.subscribe(Box::new(move || {
            record_for_threes.lock().expect("not poisoned").push(3);
        }));

        event.fire();
        assert_eq!(&[1, 2, 3], record.lock().expect("not poisoned").as_slice());

        drop(twos_subscription);
        event.fire();
        assert_eq!(
            &[1, 2, 3, 1, 3],
            record.lock().expect("not poisoned").as_slice()
        );
    }

    #[test]
    fn observable_event_handles_races_on_multiple_fires() {
        let event = Arc::new(ObservableEvent::default());

        let counter = Arc::new(AtomicU32::new(0));
        let counter_for_event = counter.clone();
        let _counter_subscription = event.subscribe(Box::new(move || {
            counter_for_event.fetch_add(1, Ordering::Relaxed);
        }));

        let (tx, rx) = tokio::sync::oneshot::channel();
        let event_for_other_thread = event.clone();
        let other_thread = std::thread::spawn(move || {
            rx.blocking_recv().expect("subscription callback is run");
            event_for_other_thread.fire();
        });

        let mut tx = Some(tx);
        let _fire_subscription = event.subscribe(Box::new(move || {
            if let Some(tx) = tx.take() {
                tx.send(()).expect("other thread is waiting");
                // We can't *guarantee* that the other thread reaches the fire before this subscription exits,
                // because it won't *return* from the fire until this thread's fire completes.
                // The best we can do is sleep, even though it makes the test longer.
                std::thread::sleep(Duration::from_millis(200));
            }
        }));

        event.fire();
        other_thread.join().expect("success");
        assert_eq!(
            2,
            counter.load(Ordering::Relaxed),
            "second call shouldn't be forgotten"
        );
    }

    #[test]
    fn observable_event_handles_race_between_fire_and_subscribe() {
        let event = Arc::new(ObservableEvent::default());

        let counter = Arc::new(AtomicU32::new(0));
        let counter_for_subscription = counter.clone();

        // Imitate a subscribe() coming in on a different thread while processing a previous fire().
        let event_for_callback = event.clone();
        let _subscription = event.subscribe(Box::new(move || {
            let counter_for_event = counter_for_subscription.clone();
            // Leak the subscription, since this is just a test.
            std::mem::forget(event_for_callback.subscribe(Box::new(move || {
                counter_for_event.fetch_add(1, Ordering::Relaxed);
            })));
        }));

        event.fire();
        assert_eq!(
            0,
            counter.load(Ordering::Relaxed),
            "subscriptions added during fire won't be invoked immediately"
        );

        event.fire();
        assert_eq!(
            1,
            counter.load(Ordering::Relaxed),
            "subscriptions added during fire shouldn't be lost"
        );

        event.fire();
        assert_eq!(
            3,
            counter.load(Ordering::Relaxed),
            "new subscriptions keep getting added"
        );
    }

    #[test]
    fn observable_event_handles_race_between_fire_and_remove() {
        let event = Arc::new(ObservableEvent::default());

        // Imitate a remove() coming in on a different thread while processing a previous fire().
        let subscription = Arc::new(std::sync::Mutex::new(None));
        let subscription_for_event = subscription.clone();
        *subscription.lock().expect("not poisoned") = Some(event.subscribe(Box::new(move || {
            drop(
                subscription_for_event
                    .lock()
                    .expect("not poisoned")
                    .take()
                    .expect("only called once"),
            );
        })));

        assert!(subscription.lock().expect("not poisoned").is_some());
        event.fire();
        assert_matches!(subscription.lock().expect("not poisoned").take(), None);

        // Make sure we actually removed the subscription.
        event.fire();
    }
}
