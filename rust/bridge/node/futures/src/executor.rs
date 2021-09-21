//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use neon::prelude::*;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Poll, Wake};

/// Adds support for executing futures on a Neon [Channel][].
///
/// [Channel]: https://docs.rs/neon/0.9.0/neon/event/struct.Channel.html
pub trait ChannelEx {
    /// Schedules the future to run on the JavaScript main thread until complete.
    fn send_future(&self, future: impl Future<Output = ()> + 'static + Send);
    /// Polls the future synchronously, then schedules it to run on the JavaScript main thread from
    /// then on.
    fn start_future(&self, future: impl Future<Output = ()> + 'static + Send);
}

impl ChannelEx for Channel {
    fn send_future(&self, future: impl Future<Output = ()> + 'static + Send) {
        let self_for_task = self.clone();
        self.send(move |_| {
            let task = Arc::new(FutureTask {
                channel: self_for_task,
                future: Mutex::new(Some(Box::pin(future))),
            });
            task.poll();
            Ok(())
        });
    }

    fn start_future(&self, future: impl Future<Output = ()> + 'static + Send) {
        let task = Arc::new(FutureTask {
            channel: self.clone(),
            future: Mutex::new(Some(Box::pin(future))),
        });
        task.poll();
    }
}

/// Used to "send" a task from a thread to itself through a multi-threaded interface.
pub(crate) struct AssertSendSafe<T>(T);
unsafe impl<T> Send for AssertSendSafe<T> {}
impl<T> AssertSendSafe<T> {
    pub unsafe fn wrap(value: T) -> Self {
        Self(value)
    }
}

impl<T: Future> Future for AssertSendSafe<T> {
    type Output = T::Output;
    fn poll(self: Pin<&mut Self>, context: &mut std::task::Context) -> Poll<T::Output> {
        // See https://doc.rust-lang.org/std/pin/index.html#projections-and-structural-pinning
        let future = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        future.poll(context)
    }
}

/// Implements waking for futures scheduled on the JavaScript microtask queue.
///
/// When the task is awoken, it reschedules itself on the channel to re-poll the top-level Future.
struct FutureTask<F>
where
    F: Future<Output = ()> + 'static + Send,
{
    channel: Channel,
    future: Mutex<Option<Pin<Box<F>>>>,
}

impl<F> FutureTask<F>
where
    F: Future<Output = ()> + 'static + Send,
{
    /// Polls the top-level future, while setting `self` up as the waker once more.
    ///
    /// When the future completes, it is replaced by `None` to avoid accidentally polling twice.
    fn poll(self: &Arc<Self>) {
        let future = &mut *self.future.lock().expect("Lock can be taken");
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
        let channel = self.channel.clone();
        channel.send(move |_cx| {
            self.poll();
            Ok(())
        });
    }
}
