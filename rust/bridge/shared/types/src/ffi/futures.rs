//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;

use futures_util::{FutureExt, TryFutureExt};

use super::*;
use crate::support::{AsyncRuntime, ResultReporter};

#[derive(Debug)]
pub struct FutureCancelled;

pub type RawCancellationId = u64;

/// A C callback used to report the results of Rust futures.
///
/// cbindgen will produce independent C types like `SignalCPromisei32` and
/// `SignalCPromiseProtocolAddress`.
///
/// This derives Copy because it behaves like a C type; nevertheless, a promise should still only be
/// completed once.
#[derive_where(Clone, Copy)]
#[repr(C)]
pub struct CPromise<T> {
    complete: extern "C" fn(
        error: *mut SignalFfiError,
        result: *const T,
        context: *const std::ffi::c_void,
    ),
    context: *const std::ffi::c_void,
    cancellation_id: RawCancellationId,
}

/// Keeps track of the information necessary to report a promise result back to C.
///
/// Because this represents a C callback that might be holding on to resources, users of
/// PromiseCompleter *must* consume it by calling [`CPromise`]'s `complete`.
/// Failure to do so will result in a panic in debug mode and an error log in
/// release mode.
pub struct PromiseCompleter<T: ResultTypeInfo> {
    promise: CPromise<T::ResultType>,
}

/// Pointers are not Send by default just in case,
/// but we just pass the promise context around opaquely without using it from Rust.
///
/// Of course, the C code has to handle the pointer being sent across threads too.
unsafe impl<T: ResultTypeInfo> Send for PromiseCompleter<T> {}

impl<T: ResultTypeInfo> Drop for PromiseCompleter<T> {
    fn drop(&mut self) {
        // Dropping a promise likely leaks resources on the other side of the bridge (whatever's in
        // promise_context). It won't bring down the application, but it definitely indicates a bug.
        debug_assert!(false, "CPromise dropped without completing");
        log::error!(
            "CPromise<{}> dropped without completing",
            std::any::type_name::<T>()
        );
    }
}

pub struct FutureResultReporter<T: ResultTypeInfo>(SignalFfiResult<T>);

impl<T: ResultTypeInfo> FutureResultReporter<T> {
    pub fn new(result: SignalFfiResult<T>) -> Self {
        // We're going to pass the value through C; if any cleanup needs to be done, it'll be done
        // manually on the C/Swift side.
        assert!(!std::mem::needs_drop::<T::ResultType>());
        Self(result)
    }
}

impl<T: ResultTypeInfo + std::panic::UnwindSafe> ResultReporter for FutureResultReporter<T> {
    type Receiver = PromiseCompleter<T>;

    fn report_to(self, completer: Self::Receiver) {
        let Self(result) = self;
        let PromiseCompleter { promise } = completer;
        // Disable the check for uncompleted promises in our Drop before we do anything else.
        std::mem::forget(completer);

        let result = result.and_then(|result| {
            std::panic::catch_unwind(|| result.convert_into())
                .unwrap_or_else(|panic| Err(UnexpectedPanic(panic).into()))
        });

        match result {
            Ok(value) => {
                // Imitate Swift's `sending` here: we might be passing the value by pointer,
                // but we must not use it or anything it references after that.
                (promise.complete)(std::ptr::null_mut(), &value, promise.context);
                std::mem::forget(value);
            }
            Err(err) => (promise.complete)(
                Box::into_raw(Box::new(err)),
                std::ptr::null(),
                promise.context,
            ),
        }
    }
}

/// Runs a future as a task on the given async runtime, and reports the result back to `promise`.
///
/// More specifically, this method expects `make_future` to produce a Rust Future (`F`); that Future
/// should compute some output (`O`) and report it to the given `PromiseCompleter`. This structure
/// mirrors [`crate::jni::run_future_on_runtime`], where it's necessary for cleanup.
///
/// `promise_context` is passed through unchanged.
///
/// ## Example
///
/// ```no_run
/// # use libsignal_bridge_types::ffi::*;
/// # use libsignal_bridge_types::{AsyncRuntime, ResultReporter};
/// # use libsignal_bridge_types::support::NoOpAsyncRuntime;
/// # fn test(promise: &mut CPromise<i32>, async_runtime: &NoOpAsyncRuntime) {
/// run_future_on_runtime(async_runtime, promise, |_cancel| async {
///     let result: i32 = 1 + 2;
///     // Do some complicated awaiting here.
///     FutureResultReporter::new(Ok(result))
/// });
/// # }
#[inline]
pub fn run_future_on_runtime<R, F, O>(
    runtime: &R,
    promise: &mut CPromise<O::ResultType>,
    future: impl FnOnce(R::Cancellation) -> F,
) where
    R: AsyncRuntime<F>,
    F: Future<Output: ResultReporter<Receiver = PromiseCompleter<O>>>
        + std::panic::UnwindSafe
        + 'static,
    O: ResultTypeInfo + 'static,
{
    let completion = PromiseCompleter { promise: *promise };
    let cancellation_id = runtime.run_future(future, completion);
    promise.cancellation_id = cancellation_id.into();
}

/// Catches panics that occur in `future` and converts them to a
/// [`SignalFfiError`] error containing an [`UnexpectedPanic`].
pub fn catch_unwind<T>(
    future: impl Future<Output = SignalFfiResult<T>> + Send + std::panic::UnwindSafe + 'static,
) -> impl Future<Output = SignalFfiResult<T>> + Send + std::panic::UnwindSafe + 'static {
    future
        .catch_unwind()
        .unwrap_or_else(|panic| Err(UnexpectedPanic(panic).into()))
}
