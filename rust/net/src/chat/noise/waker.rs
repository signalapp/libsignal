//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::Arc;
use std::task::{Context, Wake, Waker};

/// Manages a [`Waker`] that wakes registered read & write wakers.
///
/// Holds at most one waker for each of read and write tasks. Use
/// [`SharedWakers::as_ref`] to get a [`Waker`] that can be passed to
/// [`Context::from_waker`].
pub(super) struct SharedWakers {
    /// Inner state
    state: Arc<Inner>,
    /// The same inner state, but held as a `Waker` to avoid calling
    /// [`Waker::from`] as often.
    waker: Waker,
}

impl Default for SharedWakers {
    fn default() -> Self {
        let state = Default::default();
        Self {
            waker: Waker::from(Arc::clone(&state)),
            state,
        }
    }
}

impl AsRef<Waker> for SharedWakers {
    fn as_ref(&self) -> &Waker {
        &self.waker
    }
}

impl SharedWakers {
    pub(super) fn save_writer_from(&self, cx: &mut Context<'_>) {
        self.state
            .with_lock(|wakers| wakers.write.save_from(cx.waker()))
    }
    pub(super) fn save_reader_from(&self, cx: &mut Context<'_>) {
        self.state
            .with_lock(|wakers| wakers.read.save_from(cx.waker()))
    }
    pub(super) fn wake_writer(&self) {
        self.state
            .with_lock(|wakers| wakers.write.take())
            .wake_if_some()
    }
    pub(super) fn wake_reader(&self) {
        self.state
            .with_lock(|wakers| wakers.read.take())
            .wake_if_some()
    }
}

/// Wrapper type to allow implementing [`Wake`].
#[derive(Default)]
struct Inner(std::sync::Mutex<ReadWriteWakers>);

impl Inner {
    fn with_lock<R>(&self, f: impl FnOnce(&mut ReadWriteWakers) -> R) -> R {
        f(&mut self.0.lock().expect("not poisoned"))
    }
}

#[derive(Default)]
struct ReadWriteWakers {
    read: Option<Waker>,
    write: Option<Waker>,
}

impl Wake for Inner {
    fn wake(self: Arc<Self>) {
        let ReadWriteWakers { read, write } = self.with_lock(std::mem::take);
        read.wake_if_some();
        write.wake_if_some();
    }
}

/// Convenience trait for working with [`Option<Waker>`]s.
trait WakerExt {
    /// Logically equivalent to `*self = Some(waker.clone())`
    fn save_from(&mut self, waker: &Waker);

    /// If `self` is `Some(waker)`, wakes `waker`.
    fn wake_if_some(self);
}

impl WakerExt for Option<Waker> {
    fn save_from(&mut self, waker: &Waker) {
        match self {
            Some(saved) => saved.clone_from(waker),
            None => *self = Some(waker.clone()),
        };
    }

    fn wake_if_some(self) {
        if let Some(waker) = self {
            waker.wake()
        }
    }
}
