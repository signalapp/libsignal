//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use neon::prelude::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Poll, Wake};

/// Adds support for executing futures on a Neon [EventQueue][].
///
/// [EventQueue]: https://docs.rs/neon/0.7.0-napi.3/neon/event/struct.EventQueue.html
pub trait EventQueueEx {
    /// Schedules the future to run on the JavaScript main thread until complete.
    fn send_future(&self, future: impl Future<Output = ()> + 'static + Send);
}

impl EventQueueEx for EventQueue {
    fn send_future(&self, future: impl Future<Output = ()> + 'static + Send) {
        self.send(move |mut cx| {
            let task = Arc::new(FutureTask {
                queue: cx.queue(),
                future: Mutex::new(Some(Box::pin(future))),
            });
            task.poll();
            Ok(())
        })
    }
}

/// Used to "send" a task from a thread to itself through a multi-threaded interface.
struct AssertSendSafe<T>(T);
unsafe impl<T> Send for AssertSendSafe<T> {}

impl<T: Future> Future for AssertSendSafe<T> {
    type Output = T::Output;
    fn poll(self: Pin<&mut Self>, context: &mut std::task::Context) -> Poll<T::Output> {
        // See https://doc.rust-lang.org/std/pin/index.html#projections-and-structural-pinning
        let future = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        future.poll(context)
    }
}

/// Adds support for executing closures and futures on the JavaScript main thread's microtask queue.
pub trait ContextEx<'a>: Context<'a> {
    /// Schedules `f` to run on the microtask queue.
    ///
    /// Equivalent to `cx.queue().send(f)` except that `f` doesn't need to be `Send`.
    fn run_on_queue(&mut self, f: impl FnOnce(TaskContext<'_>) -> NeonResult<()> + 'static) {
        let f = AssertSendSafe(f);
        self.queue().send(move |cx| f.0(cx));
    }

    /// Schedules `f` to run on the microtask queue.
    ///
    /// Equivalent to `cx.queue().send_future(f)` except that `f` doesn't need to be `Send`.
    fn run_future_on_queue(&mut self, f: impl Future<Output = ()> + 'static) {
        let f = AssertSendSafe(f);
        self.queue().send_future(f);
    }
}

impl<'a, T: Context<'a>> ContextEx<'a> for T {}

/// Implements waking for futures scheduled on the JavaScript microtask queue.
///
/// When the task is awoken, it reschedules itself on the task queue to re-poll the top-level Future.
struct FutureTask<F>
where
    F: Future<Output = ()> + 'static + Send,
{
    queue: EventQueue,
    future: Mutex<Option<Pin<Box<F>>>>,
}

impl<F> FutureTask<F>
where
    F: Future<Output = ()> + 'static + Send,
{
    /// Polls the top-level future, while setting `self` up as the waker once more.
    ///
    /// When the future completes, it is replaced by `None` to avoid accidentally polling twice.
    fn poll(self: Arc<Self>) {
        let future = &mut *self.future.lock().unwrap();
        if let Some(active_future) = future {
            match active_future
                .as_mut()
                .poll(&mut std::task::Context::from_waker(&self.clone().into()))
            {
                Poll::Ready(_) => *future = None,
                Poll::Pending => {}
            }
        }
    }
}

impl<F> Wake for FutureTask<F>
where
    F: Future<Output = ()> + 'static + Send,
{
    fn wake(self: Arc<Self>) {
        let self_for_closure = self.clone();
        self.queue.send(move |_cx| {
            self_for_closure.poll();
            Ok(())
        })
    }
}
