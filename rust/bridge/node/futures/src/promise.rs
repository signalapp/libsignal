//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures_util::FutureExt;
use neon::prelude::*;
use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe, UnwindSafe};
use std::sync::Arc;

use crate::executor::{AssertSendSafe, ChannelEx};
use crate::util::describe_panic;
use crate::*;

const RESOLVE_SLOT: &str = "_resolve";
const REJECT_SLOT: &str = "_reject";

/// A JavaScript-compatible function that saves its first two arguments as `this._resolve` and `this._reject`.
fn save_promise_callbacks(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let this = cx.this();

    let resolve = cx.argument::<JsFunction>(0)?;
    this.set(&mut cx, RESOLVE_SLOT, resolve)?;

    let reject = cx.argument::<JsFunction>(1)?;
    this.set(&mut cx, REJECT_SLOT, reject)?;

    Ok(cx.undefined())
}

/// Produces a JavaScript Promise that represents the result of a Rust computation.
///
/// There's a lot going on here, so let's break it down:
/// - `future` must return a "settle" function, or fail with a JavaScript error stored as a PersistentException.
/// - The "settle" function (`F`) must produce a result in a synchronous JavaScript context, or fail with a JavaScript exception.
/// - That value (`V`) will be the final result of the JavaScript Promise.
/// - If there are any failures during the evaluation of the future or "settle" function, they will result in the rejection of the Promise.
/// - If there are any panics during the evaluation of the future or "settle" function, they will be translated to JavaScript Errors (per Neon conventions).
///
/// In practice, this is going to be the easiest way to produce a JavaScript Promise, especially for safely handling errors.
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
/// fn js_compute_result(mut cx: FunctionContext) -> JsResult<JsObject> {
///     let js_info = cx.argument::<JsObject>(0)?;
///     let trait_impl = TraitImpl::new(cx.channel(), js_info.root(&mut cx));
///     promise(&mut cx, async move {
///         let result = compute_result(trait_impl).await?;
///         settle_promise(move |cx| Ok(cx.string(result)))
///     })
/// }
/// ```
pub fn promise<'a, V, F>(
    cx: &mut FunctionContext<'a>,
    future: impl Future<Output = Result<F, PersistentException>> + UnwindSafe + 'static,
) -> JsResult<'a, JsObject>
where
    V: neon::types::Value,
    F: for<'b> FnOnce(&mut TaskContext<'b>) -> JsResult<'b, V> + Send + UnwindSafe + 'static,
{
    let callbacks_object = cx.empty_object();
    let save_promise_callbacks_fn = JsFunction::new(cx, save_promise_callbacks)?;
    let bound_save_promise_callbacks = call_method(
        cx,
        save_promise_callbacks_fn,
        "bind",
        vec![callbacks_object.upcast()],
    )?;

    let promise_ctor: Handle<JsFunction> = cx.global().get(cx, "Promise")?.downcast_or_throw(cx)?;
    let promise = promise_ctor.construct(cx, vec![bound_save_promise_callbacks])?;

    let callbacks_object_root = callbacks_object.root(cx);
    let channel = Arc::new(cx.channel());
    let channel_for_future = channel.clone();

    let future = async move {
        let result: std::thread::Result<Result<F, PersistentException>> =
            future.catch_unwind().await;

        channel_for_future.send(move |mut cx| -> NeonResult<()> {
            let settled_result: std::thread::Result<Result<Handle<V>, Handle<JsValue>>> =
                match result {
                    Ok(Ok(settle)) => {
                        // This AssertUnwindSafe is not technically safe.
                        // If we get a panic downstream, it is entirely possible the JavaScript context won't be usable anymore.
                        // However, that's no more unsafe than JsAsyncContext::with_context,
                        // or for that matter Neon automatically catching panics by default.
                        let mut cx = AssertUnwindSafe(&mut cx);
                        catch_unwind(move || cx.try_catch(|cx| settle(cx)))
                    }
                    Ok(Err(exception)) => Ok(Err(exception.into_inner(&mut cx))),
                    Err(panic) => Err(panic),
                };

            let folded_result: Result<Handle<V>, Handle<JsValue>> =
                settled_result.unwrap_or_else(|panic| {
                    Err(cx
                        .error(format!("unexpected panic: {}", describe_panic(&panic)))
                        .expect("can create an Error")
                        .upcast())
                });

            let callbacks_object = callbacks_object_root.into_inner(&mut cx);

            match folded_result {
                Ok(value) => {
                    call_method(
                        &mut cx,
                        callbacks_object,
                        RESOLVE_SLOT,
                        vec![value.upcast()],
                    )?;
                }
                Err(exception) => {
                    call_method(&mut cx, callbacks_object, REJECT_SLOT, vec![exception])?;
                }
            }

            Ok(())
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
