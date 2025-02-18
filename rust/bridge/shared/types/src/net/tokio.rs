//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use futures_util::future::BoxFuture;
use futures_util::FutureExt as _;

use crate::support::*;
use crate::*;
pub struct TokioAsyncContext {
    pub(crate) rt: tokio::runtime::Runtime,
    tasks: Arc<Mutex<HashMap<CancellationId, tokio::sync::oneshot::Sender<()>>>>,
    next_raw_cancellation_id: AtomicU64,
}

impl TokioAsyncContext {
    // This is an expensive operation, so we don't want to just use Default.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            rt: tokio::runtime::Builder::new_multi_thread()
                .enable_io()
                .enable_time()
                .thread_name("libsignal-tokio-worker")
                .build()
                .expect("failed to create runtime"),
            tasks: Default::default(),
            next_raw_cancellation_id: AtomicU64::new(1),
        }
    }

    pub fn handle(&self) -> tokio::runtime::Handle {
        self.rt.handle().clone()
    }
}

/// Assert [`TokioAsyncContext`] is unwind-safe.
///
/// [`tokio::runtime::Runtime`] handles panics in spawned tasks internally, and
/// spawning a task on it shouldn't cause logic errors if that panics.
///
/// (...but do be careful not to hold the `tasks` lock over a potential panic.)
impl std::panic::RefUnwindSafe for TokioAsyncContext {}

bridge_as_handle!(TokioAsyncContext);

pub struct TokioContextCancellation(tokio::sync::oneshot::Receiver<()>);

impl Future for TokioContextCancellation {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // Treat both sends and closes as completion.
        self.0.poll_unpin(cx).map(|_| ())
    }
}

// Not ideal! tokio doesn't promise that a oneshot::Receiver is in fact panic-safe.
// But its interior mutable state is only modified by the Receiver while it's being polled,
// and that means a panic would have to happen inside Receiver itself to cause a problem.
// Combined with our payload type being (), it's unlikely this can happen in practice.
impl std::panic::UnwindSafe for TokioContextCancellation {}

impl AsyncRuntimeBase for TokioAsyncContext {
    fn cancel(&self, cancellation_token: CancellationId) {
        if cancellation_token == CancellationId::NotSupported {
            log::warn!("ignoring invalid cancellation ID");
            return;
        }
        let maybe_cancel_tx = self
            .tasks
            .lock()
            .expect("task map isn't poisoned")
            .remove(&cancellation_token);
        // Either there's an active task and this will Drop its cancellation Sender,
        // or there's no matching task and this will do nothing.
        // (The explicit drop is to make it clear that this doesn't happen inside the lock.)
        if maybe_cancel_tx.is_some() {
            log::trace!("cancelling task for {cancellation_token:?}");
        } else {
            log::trace!("ignoring cancellation for task {cancellation_token:?} (probably completed already)");
        }
        drop(maybe_cancel_tx);
    }
}

impl<F> AsyncRuntime<F> for TokioAsyncContext
where
    F: Future<Output: ResultReporter<Receiver: Send> + Send> + Send + 'static,
{
    type Cancellation = TokioContextCancellation;

    fn run_future(
        &self,
        make_future: impl FnOnce(TokioContextCancellation) -> F,
        completer: <F::Output as ResultReporter>::Receiver,
    ) -> CancellationId {
        // Delegate to a non-templated function with dynamic dispatch to save on
        // compiled code size.
        self.run_future_boxed(Box::new(move |cancellation| {
            let future = make_future(cancellation);
            async {
                let reporter = future.await;
                let report_cb: Box<dyn FnOnce() + Send> =
                    Box::new(move || reporter.report_to(completer));
                report_cb
            }
            .boxed()
        }))
    }
}

type ReportResultBoxed = Box<dyn FnOnce() + Send>;

impl TokioAsyncContext {
    /// Create and spawn a `Future` as a task, then spawn a blocking task to
    /// execute the output callback.
    ///
    /// This intentionally uses dynamic dispatch to save on code size. Future
    /// spawning in templated code (that gets duplicated during
    /// monomorphization) should call this method with a callback of the
    /// appropriate type.
    fn run_future_boxed<'s>(
        &'s self,
        make_future: Box<
            dyn 's + FnOnce(TokioContextCancellation) -> BoxFuture<'static, ReportResultBoxed>,
        >,
    ) -> CancellationId {
        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();

        let cancellation_id = CancellationId::from(
            self.next_raw_cancellation_id
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        );
        debug_assert_ne!(cancellation_id, CancellationId::NotSupported);
        let previous_cancel_tx = self
            .tasks
            .lock()
            .expect("task map isn't poisoned")
            .insert(cancellation_id, cancel_tx);
        debug_assert!(
            previous_cancel_tx.is_none(),
            "shouldn't reuse cancellation IDs"
        );

        let future = make_future(TokioContextCancellation(cancel_rx));

        let handle = self.rt.handle().clone();
        let task_map_weak = Arc::downgrade(&self.tasks);

        #[allow(clippy::let_underscore_future)]
        let _: tokio::task::JoinHandle<()> = self.rt.spawn(async move {
            let report_fn = future.await;
            let _: tokio::task::JoinHandle<()> = handle.spawn_blocking(report_fn);
            // What happens if we don't get here? We leak an entry in the task map. Also, we
            // probably have bigger problems, because in practice all the `bridge_io` futures are
            // supposed to be catching panics.
            if let Some(task_map) = task_map_weak.upgrade() {
                task_map
                    .lock()
                    .expect("task map isn't poisoned")
                    .remove(&cancellation_id);
            }
            log::trace!("completed task with {cancellation_id:?}");
        });

        log::trace!("started task with {cancellation_id:?}");
        cancellation_id
    }
}

#[cfg(test)]
mod test {
    use std::future::Future;
    use std::sync::{Arc, Mutex};

    use assert_matches::assert_matches;
    use tokio::sync::{mpsc, oneshot};

    use super::*;

    /// [`ResultReporter`] that notifies when it starts reporting.
    struct NotifyingReporter<R> {
        on_start_reporting: oneshot::Sender<()>,
        reporter: R,
    }

    impl<R: ResultReporter> ResultReporter for NotifyingReporter<R> {
        type Receiver = R::Receiver;
        fn report_to(self, completer: Self::Receiver) {
            self.on_start_reporting
                .send(())
                .expect("listener not dropped");
            self.reporter.report_to(completer)
        }
    }

    impl<T> ResultReporter for (T, Arc<Mutex<Option<T>>>) {
        type Receiver = ();
        fn report_to(self, (): ()) {
            *self.1.lock().expect("not poisoned") = Some(self.0);
        }
    }

    /// [`ResultReporter`] that does nothing with its result.
    struct DiscardingReporter;

    impl ResultReporter for DiscardingReporter {
        type Receiver = ();
        fn report_to(self, (): ()) {}
    }

    fn sum_task<T: std::ops::Add>() -> (
        mpsc::UnboundedSender<(T, T)>,
        mpsc::UnboundedReceiver<T::Output>,
        impl Future<Output = ()>,
    ) {
        let (input_tx, mut input_rx) = mpsc::unbounded_channel();
        let (output_tx, output_rx) = mpsc::unbounded_channel();
        let future = async move {
            while let Some((a, b)) = input_rx.recv().await {
                output_tx.send(a + b).expect("receiver available");
            }
        };

        (input_tx, output_rx, future)
    }

    #[test]
    fn async_tokio_runtime_reporting_does_not_block() {
        // We want to prove that even if result reporting blocks, other tasks on
        // the same runtime can make progress. We can verify this with a task
        // that will sum anything we send it. We then check that if another task
        // is blocked on reporting its result, the summing task still works.

        // Create a runtime with one worker thread running in the background.
        let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
        runtime_builder.worker_threads(1);
        let runtime = runtime_builder.build().expect("valid runtime");

        // Create a task that will sum anything it is sent.
        let (sum_tx, mut sum_rx, sum_future) = sum_task();
        runtime.spawn(sum_future);

        let async_context = TokioAsyncContext {
            rt: runtime,
            tasks: Default::default(),
            next_raw_cancellation_id: AtomicU64::new(1),
        };

        let (send_to_task, task_output, when_reporting) = {
            let (sender, receiver) = oneshot::channel();
            let (on_start_reporting, when_reporting) = oneshot::channel();
            let output = Arc::new(Mutex::new(None));
            let task_output = output.clone();
            async_context.run_future(
                |_cancel| async move {
                    let result = receiver.await.expect("sender not dropped");

                    NotifyingReporter {
                        on_start_reporting,
                        reporter: (result, task_output.clone()),
                    }
                },
                (),
            );
            (sender, output, when_reporting)
        };

        // Now both futures are running, so we should be able to communicate
        // with the sum task.
        sum_tx.send((100, 10)).expect("receiver running");
        sum_tx.send((80, 90)).expect("receiver running");
        assert_eq!(sum_rx.blocking_recv(), Some(110));
        assert_eq!(sum_rx.blocking_recv(), Some(170));

        const FUTURE_RESULT: &str = "eventual result";

        // Lock the mutex and allow the future to complete and to begin the
        // reporting phase. Reporting will be blocked, but the sum task should
        // still be able to make progress.
        let lock = task_output.lock().expect("not poisoned");
        send_to_task.send(FUTURE_RESULT).expect("task is running");
        assert_eq!(*lock, None);
        when_reporting.blocking_recv().expect("sender exists");

        sum_tx.send((300, 33)).expect("receiver exists");
        assert_eq!(sum_rx.blocking_recv(), Some(333));

        // Unlock the mutex. This will allow the result to be reported.
        drop(lock);
        // Dropping the runtime will block waiting for all blocking tasks to
        // finish.
        drop(async_context);
        let result = Arc::into_inner(task_output)
            .expect("no other references")
            .into_inner()
            .expect("not poisoned");
        assert_eq!(result, Some(FUTURE_RESULT));
    }

    #[test]
    fn cancellation() {
        // Create a runtime with one worker thread running in the background.
        let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
        runtime_builder.worker_threads(1);
        let runtime = runtime_builder.build().expect("valid runtime");

        let async_context = TokioAsyncContext {
            rt: runtime,
            tasks: Default::default(),
            next_raw_cancellation_id: AtomicU64::new(1),
        };

        let (on_start_reporting1, mut when_reporting1) = oneshot::channel();
        let cancellation_id1 = async_context.run_future(
            |cancel| async move {
                cancel.await;
                NotifyingReporter {
                    on_start_reporting: on_start_reporting1,
                    reporter: DiscardingReporter,
                }
            },
            (),
        );

        let (on_start_reporting2, mut when_reporting2) = oneshot::channel();
        let cancellation_id2 = async_context.run_future(
            |cancel| async move {
                cancel.await;
                NotifyingReporter {
                    on_start_reporting: on_start_reporting2,
                    reporter: DiscardingReporter,
                }
            },
            (),
        );

        assert_matches!(
            when_reporting1.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );
        assert_matches!(
            when_reporting2.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );

        async_context.cancel(cancellation_id2);
        when_reporting2.blocking_recv().expect("completed");
        assert_matches!(
            when_reporting1.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );

        async_context.cancel(cancellation_id1);
        when_reporting1.blocking_recv().expect("completed");
    }
}
