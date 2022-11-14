//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures_util::FutureExt;
use neon::prelude::*;
use neon::types::JsPromise;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe, UnwindSafe};

use crate::executor::{AssertSendSafe, ChannelEx};
use crate::util::describe_panic;
use crate::*;

/// Produces a JavaScript Promise that represents the result of a Rust future.
///
/// There's a lot going on here, so let's break it down:
/// - `future` must return a "settle" function, or fail with a JavaScript error stored as a PersistentException.
/// - The "settle" function (`F`) must produce a result in a synchronous JavaScript context, or fail with a JavaScript exception.
/// - That value (`V`) will be the final result of the JavaScript Promise.
/// - If there are any failures during the evaluation of the future or "settle" function, they will result in the rejection of the Promise.
/// - If there are any panics during the evaluation of the future or "settle" function, they will be translated to JavaScript Errors (per Neon conventions).
///
/// In practice, this is going to be the easiest way to produce a JavaScript Promise, especially for safely handling errors. You can also use Neon's [`Context::promise`][] API for more control, at the cost of catching panics and scheduling the future yourself.
///
/// ```no_run
/// # use neon::prelude::*;
/// # use signal_neon_futures::*;
/// #
/// # struct TraitImpl;
/// # impl TraitImpl {
/// #   fn new(channel: Channel, info: Root<JsObject>) -> Self { Self }
/// # }
/// # async fn compute_result(t: TraitImpl) -> Result<String, PersistentException> { Ok("abc".into()) }
/// #
/// fn js_compute_result(mut cx: FunctionContext) -> JsResult<JsPromise> {
///     let js_info = cx.argument::<JsObject>(0)?;
///     let trait_impl = TraitImpl::new(cx.channel(), js_info.root(&mut cx));
///     promise(&mut cx, async move {
///         let result = compute_result(trait_impl).await?;
///         settle_promise(move |cx| Ok(cx.string(result)))
///     })
/// }
/// ```
///
/// [`Context::promise`]: neon::context::Context::promise
pub fn promise<'a, V, F>(
    cx: &mut FunctionContext<'a>,
    future: impl Future<Output = Result<F, PersistentException>> + UnwindSafe + 'static,
) -> JsResult<'a, JsPromise>
where
    V: neon::types::Value,
    F: for<'b> FnOnce(&mut TaskContext<'b>) -> JsResult<'b, V> + Send + UnwindSafe + 'static,
{
    let (deferred, promise) = cx.promise();
    let channel = cx.channel();
    let channel_for_future = channel.clone();

    let future = async move {
        let result: std::thread::Result<Result<F, PersistentException>> =
            future.catch_unwind().await;

        deferred.settle_with(&channel_for_future, move |mut cx| {
            let settled_result: std::thread::Result<JsResult<V>> = match result {
                Ok(Ok(settle)) => {
                    // This AssertUnwindSafe is not technically safe.
                    // If we get a panic downstream, it is entirely possible the JavaScript context won't be usable anymore.
                    // However, the only thing we're going to do with the context after a panic is throw an error.
                    let mut cx = AssertUnwindSafe(&mut cx);
                    // Auto-deref does not actually kick in here.
                    #[allow(clippy::explicit_auto_deref)]
                    catch_unwind(move || settle(*cx))
                }
                Ok(Err(exception)) => {
                    let exception = exception.into_inner(&mut cx);
                    Ok(cx.throw(exception))
                }
                Err(panic) => Err(panic),
            };

            settled_result.unwrap_or_else(|panic| {
                cx.throw_error(format!("unexpected panic: {}", describe_panic(&panic)))
            })
        });
    };

    // AssertSendSafe because `channel` is running on the same thread as the current context `cx`,
    // so in practice we are always on the same thread.
    let future = unsafe { AssertSendSafe::wrap(future) };
    channel.start_future(future);

    Ok(promise)
}

/// Use this to return your "settle" function when using [promise()].
///
/// This works around a bug in the Rust compiler by providing extra type information.
/// It is equivalent to [Ok].
pub fn settle_promise<C, T, E>(callback: C) -> Result<C, E>
where
    T: Value,
    C: for<'a> FnOnce(&mut TaskContext<'a>) -> JsResult<'a, T>,
{
    Ok(callback)
}
