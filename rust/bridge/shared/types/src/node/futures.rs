//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::marker::PhantomData;

use futures_util::FutureExt;
use neon::types::{Deferred, JsBigInt};
use signal_neon_futures::ChannelEx;

use super::*;
use crate::support::{
    describe_panic, AsyncRuntime, AsyncRuntimeBase, CancellationId, ResultReporter,
};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
/// Promise cancelled
pub struct CancellationError;

/// Used to settle a Node Promise from any thread.
pub struct PromiseSettler<T, E> {
    deferred: Deferred,
    channel: Channel,
    error_module: Root<JsObject>,
    node_function_name: &'static str,
    complete_signature: PhantomData<fn(Result<T, E>)>,
}

impl<T, E> PromiseSettler<T, E>
where
    T: for<'a> ResultTypeInfo<'a> + std::panic::UnwindSafe + Send + 'static,
    E: SignalNodeError + Send + 'static,
{
    /// Stores the information necessary to complete a JavaScript Promise.
    ///
    /// The `this` object of `cx` is assumed to contain error types in case the Promise is settled
    /// with a failure. See [`SignalNodeError`] for more information.
    pub fn new(
        cx: &mut FunctionContext,
        deferred: Deferred,
        node_function_name: &'static str,
    ) -> Self {
        let channel = cx.channel();
        let error_module = cx
            .this::<JsObject>()
            .expect("'this' is the module containing errors, which is a valid object")
            .root(cx);
        Self {
            deferred,
            channel,
            error_module,
            node_function_name,
            complete_signature: PhantomData,
        }
    }
}

/// [`ResultReporter`] that finalizes values after converting the outcome to a
/// JS value and reporting it.
pub struct FutureResultReporter<T, E, U> {
    to_finalize: U,
    result: std::thread::Result<Result<Result<T, E>, CancellationError>>,
}

impl<T, E, U: Finalize + Send + 'static> FutureResultReporter<T, E, U> {
    pub fn new(
        result: std::thread::Result<Result<Result<T, E>, CancellationError>>,
        to_finalize: U,
    ) -> Self {
        Self {
            to_finalize,
            result,
        }
    }
}

impl<T, E, U> ResultReporter for FutureResultReporter<T, E, U>
where
    T: for<'a> ResultTypeInfo<'a> + std::panic::UnwindSafe + Send + 'static,
    E: SignalNodeError + Send + 'static,
    U: Finalize + Send + 'static,
{
    type Receiver = PromiseSettler<T, E>;
    /// Converts `result` to a JS value and completes the promise in `self`.
    ///
    /// Additionally, finalizes `extra_args_to_finalize` while completing the promise.
    /// This is important if `extra_args_to_finalize` contains root references to JS objects,
    /// or other data that requires a Neon context to clean up.
    fn report_to(self, receiver: Self::Receiver) {
        let Self {
            result,
            to_finalize: extra_args_to_finalize,
        } = self;
        let PromiseSettler {
            deferred,
            channel,
            error_module,
            node_function_name,
            complete_signature: _,
        } = receiver;

        deferred.settle_with(&channel, move |mut cx| {
            // Finalize all the extra args and unwrap our globals before anything else, so we don't
            // leak anything.
            extra_args_to_finalize.finalize(&mut cx);
            let error_module = error_module.into_inner(&mut cx);

            // If we didn't panic during execution of the future, we can convert the result to a
            // JavaScript value or error. But we might panic during *that* operation, so we'll run
            // *that* inside `catch_unwind` as well. (Neon catches panics too, but if we do it
            // manually we can include `node_function_name`.)
            let settled_result: std::thread::Result<JsResult<JsValue>> =
                result.and_then(|result| {
                    // This AssertUnwindSafe is not technically safe.
                    // If we get a panic downstream, it is entirely possible the JavaScript context
                    // won't be usable anymore.
                    // But if the panic is in *our* code, the context will be fine.
                    // And if Neon panics, there's not much we can do about it.
                    let mut cx = std::panic::AssertUnwindSafe(&mut cx);
                    match result {
                        Ok(Ok(success)) => std::panic::catch_unwind(move || {
                            Ok(success.convert_into(*cx)?.upcast())
                        }),
                        Ok(Err(failure)) => {
                            let throwable =
                                failure.into_throwable(*cx, error_module, node_function_name);
                            Ok(cx.throw(throwable))
                        }
                        Err(CancellationError) => {
                            let throwable = CancellationError.into_throwable(
                                *cx,
                                error_module,
                                node_function_name,
                            );
                            Ok(cx.throw(throwable))
                        }
                    }
                });

            settled_result.unwrap_or_else(|panic| {
                cx.throw_error(format!(
                    "unexpected panic completing {}: {}",
                    node_function_name,
                    describe_panic(&panic)
                ))
            })
        });
    }
}

/// Runs a future as a task on the given async runtime, and saves the result in a new JS Promise
/// (the return value).
///
/// More specifically, this method expects `make_future` to produce a Rust Future (`F`); that Future
/// should compute some output (`O`) or fail with an error (`E`) and report it to the given
/// `PromiseSettler`. This complex arrangement allows the Rust Future to clean up any saved data
/// that needs a Neon context.
///
/// ## Example
///
/// ```no_run
/// # use futures_util::FutureExt;
/// # use neon::prelude::*;
/// # use libsignal_bridge_types::node::*;
/// # use libsignal_bridge_types::support::NoOpAsyncRuntime;
/// # struct MyError;
/// # impl std::fmt::Display for MyError {
/// #   fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { unimplemented!() }
/// # }
/// # impl SignalNodeError for MyError {}
/// # fn test(cx: &mut FunctionContext, async_runtime: &NoOpAsyncRuntime) -> NeonResult<()> {
/// let js_promise = run_future_on_runtime(cx, async_runtime, "example", |_cancel| async {
///     let future = async {
///         let result: i32 = 1 + 2;
///         // Do some complicated awaiting here.
///         Ok(Ok::<_, MyError>(result))
///     }.catch_unwind();
///     FutureResultReporter::new(future.await, ())
/// })?;
/// # Ok(())
/// # }
pub fn run_future_on_runtime<'cx, R, F, O, E>(
    cx: &mut FunctionContext<'cx>,
    runtime: &R,
    node_function_name: &'static str,
    future: impl FnOnce(R::Cancellation) -> F,
) -> JsResult<'cx, JsPromise>
where
    R: AsyncRuntime<F>,
    F: Future<Output: ResultReporter<Receiver = PromiseSettler<O, E>>>
        + std::panic::UnwindSafe
        + 'static,
    O: for<'a> ResultTypeInfo<'a> + Send + std::panic::UnwindSafe + 'static,
    E: SignalNodeError + Send + 'static,
{
    let (deferred, promise) = cx.promise();
    let completer = PromiseSettler::new(cx, deferred, node_function_name);
    let cancellation_token = runtime.run_future(future, completer);
    if cancellation_token != CancellationId::NotSupported {
        let js_cancellation_token = JsBigInt::from_u64(cx, cancellation_token.into());
        promise.set(cx, "_cancellationToken", js_cancellation_token)?;
    }
    Ok(promise)
}

/// Wraps [`FutureExt::catch_unwind`].
///
/// Only here for consistency with the other bridges, which can treat panic errors uniformly with
/// their other error types.
pub fn catch_unwind<F>(future: F) -> futures_util::future::CatchUnwind<F>
where
    F: Future + std::panic::UnwindSafe,
{
    future.catch_unwind()
}

/// Used to "send" a task from a thread to itself through a multi-threaded interface.
struct AssertSendSafe<T>(T);
unsafe impl<T> Send for AssertSendSafe<T> {}

/// Pass a Future implementation on to the wrapped value.
impl<T: Future> Future for AssertSendSafe<T> {
    type Output = T::Output;
    fn poll(
        self: std::pin::Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> std::task::Poll<T::Output> {
        // See https://doc.rust-lang.org/std/pin/index.html#projections-and-structural-pinning
        let future = unsafe { self.map_unchecked_mut(|s| &mut s.0) };
        future.poll(context)
    }
}

/// A wrapper around [`neon::event::Channel`] that restricts direct use to the Neon Context where it was
/// created.
///
/// This allows us to implement [`AsyncRuntime`] for non-Send Futures: we start them here, on the
/// JavaScript thread, and execute them using [`signal_neon_futures::ChannelEx::start_future`], so
/// they are always polled from the JavaScript thread.
pub struct ChannelOnItsOriginalThread<'a> {
    channel: Channel,
    lifetime: PhantomData<&'a ()>,
}

impl<'a> ChannelOnItsOriginalThread<'a> {
    pub fn new(cx: &mut impl Context<'a>) -> Self {
        Self {
            channel: cx.channel(),
            lifetime: PhantomData,
        }
    }
}

impl AsyncRuntimeBase for ChannelOnItsOriginalThread<'_> {}

impl<F> AsyncRuntime<F> for ChannelOnItsOriginalThread<'_>
where
    F: Future<Output: ResultReporter<Receiver: Send>> + 'static,
{
    // Cancellation isn't supported at this time.
    type Cancellation = std::future::Pending<()>;

    fn run_future(
        &self,
        make_future: impl FnOnce(Self::Cancellation) -> F,
        completer: <F::Output as ResultReporter>::Receiver,
    ) -> CancellationId {
        // Because we're on the JS main thread, we don't need `future` to be Send; it will only be
        // run synchronously with other JS tasks by the Node microtask queue.
        let future = AssertSendSafe(make_future(std::future::pending()));
        // Note that this will poll the future *synchronously* first, to minimize context switches.
        self.channel.start_future(async move {
            future.await.report_to(completer);
        });
        CancellationId::NotSupported
    }
}
