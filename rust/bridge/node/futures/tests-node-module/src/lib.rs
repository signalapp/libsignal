//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use neon::prelude::*;
use signal_neon_futures::*;

mod panics_and_throws;
use panics_and_throws::*;

mod store_like;
use store_like::*;

// function incrementAsync(promise: Promise<number>, resolve: (number | string) => void): void
fn increment_async(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    // A complicated test that manually calls a callback at its conclusion.
    let promise = cx.argument::<JsObject>(0)?;
    let completion_callback = cx.argument::<JsFunction>(1)?.root(&mut cx);
    let queue = cx.queue();

    let future = JsFuture::await_promise(&mut cx, promise, |cx, result| match result {
        Ok(value) => Ok(value
            .downcast::<JsNumber, _>(cx)
            .expect("is number")
            .value(cx)),
        Err(err) => Err(err.to_string(cx).unwrap().value(cx)),
    })?;

    cx.run_future_on_queue(async move {
        let value_or_error = future.await;
        queue.send(move |mut cx| {
            let new_value = match value_or_error {
                Ok(value) => cx.number(value + 1.0).upcast::<JsValue>(),
                Err(ref message) => cx.string(format!("error: {}", message)).upcast::<JsValue>(),
            };
            let undefined = cx.undefined();
            completion_callback
                .into_inner(&mut cx)
                .call(&mut cx, undefined, vec![new_value])
                .expect("call succeeds");
            Ok(())
        });
    });

    Ok(cx.undefined())
}

// function incrementPromise(promise: Promise<number>): Promise<number>
fn increment_promise(mut cx: FunctionContext) -> JsResult<JsObject> {
    // A much simpler variant that uses the higher abstractions provided by promise.
    let promise = cx.argument::<JsObject>(0)?;
    let future = JsFuture::await_promise(&mut cx, promise, move |cx, result| {
        PersistentException::try_catch(cx, |cx| {
            let value = result.or_else(|e| cx.throw(e))?;
            Ok(value.downcast_or_throw::<JsNumber, _>(cx)?.value(cx))
        })
    })?;

    signal_neon_futures::promise(&mut cx, async move {
        let value = future.await?;
        fulfill_promise(move |cx| Ok(cx.number(value + 1.0)))
    })
}

register_module!(mut cx, {
    cx.export_function("incrementAsync", increment_async)?;
    cx.export_function("incrementPromise", increment_promise)?;

    cx.export_function("doubleNameFromStore", double_name_from_store)?;
    cx.export_function(
        "doubleNameFromStoreUsingJoin",
        double_name_from_store_using_join,
    )?;

    cx.export_function("panicPreAwait", panic_pre_await)?;
    cx.export_function("panicDuringCallback", panic_during_callback)?;
    cx.export_function("panicPostAwait", panic_post_await)?;
    cx.export_function("panicDuringFulfill", panic_during_fulfill)?;

    cx.export_function("throwPreAwait", throw_pre_await)?;
    cx.export_function("throwDuringCallback", throw_during_callback)?;
    cx.export_function("throwPostAwait", throw_post_await)?;
    cx.export_function("throwDuringFulfill", throw_during_fulfill)?;

    Ok(())
});
