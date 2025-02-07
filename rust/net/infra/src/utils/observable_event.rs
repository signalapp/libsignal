//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::sync::Arc;
use std::time::Duration;

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

#[cfg(test)]
mod test {

    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use assert_matches::assert_matches;

    use super::*;

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
