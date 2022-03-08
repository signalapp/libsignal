//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use neon::prelude::*;
use signal_neon_futures::*;
use std::sync::Arc;

mod panics_and_throws;
use panics_and_throws::*;

mod store_like;
use store_like::*;

// function incrementAsync(promise: Promise<number>, resolve: (number | string) => void): void
fn increment_async(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    // A complicated test that manually calls a callback at its conclusion.
    let promise = cx.argument::<JsObject>(0)?;
    let completion_callback = cx.argument::<JsFunction>(1)?.root(&mut cx);
    let channel = Arc::new(cx.channel());

    let future = JsFuture::from_promise(&mut cx, promise, |cx, result| match result {
        Ok(value) => Ok(value
            .downcast::<JsNumber, _>(cx)
            .expect("is number")
            .value(cx)),
        Err(err) => Err(err.to_string(cx).unwrap().value(cx)),
    })?;

    channel.clone().start_future(async move {
        let value_or_error = future.await;
        channel.send(move |mut cx| {
            let new_value = match value_or_error {
                Ok(value) => cx.number(value + 1.0).upcast::<JsValue>(),
                Err(ref message) => cx.string(format!("error: {}", message)).upcast::<JsValue>(),
            };
            let undefined = cx.undefined();
            completion_callback
                .into_inner(&mut cx)
                .call(&mut cx, undefined, [new_value])
                .expect("call succeeds");
            Ok(())
        });
    });

    Ok(cx.undefined())
}

// function incrementPromise(promise: Promise<number>): Promise<number>
fn increment_promise(mut cx: FunctionContext) -> JsResult<JsPromise> {
    // A much simpler variant that uses the higher abstractions provided by promise.
    let promise = cx.argument::<JsObject>(0)?;
    let future = JsFuture::from_promise(&mut cx, promise, move |cx, result| {
        cx.try_catch(|cx| {
            let value = result.or_else(|e| cx.throw(e))?;
            Ok(value.downcast_or_throw::<JsNumber, _>(cx)?.value(cx))
        })
        .map_err(|e| PersistentException::new(cx, e))
    })?;

    signal_neon_futures::promise(&mut cx, async move {
        let value = future.await?;
        settle_promise(move |cx| Ok(cx.number(value + 1.0)))
    })
}

// function incrementCallbackPromise(promise: () -> Promise<number>): Promise<number>
fn increment_callback_promise(mut cx: FunctionContext) -> JsResult<JsPromise> {
    // Like increment_promise, but with a callback step to produce the promise.
    // More closely mimics the store-like tests while still being lightweight.
    let callback = cx.argument::<JsFunction>(0)?;
    let undefined = cx.undefined();
    let promise = callback
        .call(&mut cx, undefined, [])?
        .downcast_or_throw(&mut cx)?;
    let future = JsFuture::from_promise(&mut cx, promise, move |cx, result| {
        cx.try_catch(|cx| {
            let value = result.or_else(|e| cx.throw(e))?;
            Ok(value.downcast_or_throw::<JsNumber, _>(cx)?.value(cx))
        })
        .map_err(|e| PersistentException::new(cx, e))
    })?;

    signal_neon_futures::promise(&mut cx, async move {
        let value = future.await?;
        settle_promise(move |cx| Ok(cx.number(value + 1.0)))
    })
}

#[neon::main]
fn register(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("incrementAsync", increment_async)?;
    cx.export_function("incrementPromise", increment_promise)?;
    cx.export_function("incrementCallbackPromise", increment_callback_promise)?;

    cx.export_function("doubleNameFromStore", double_name_from_store)?;
    cx.export_function(
        "doubleNameFromStoreUsingJoin",
        double_name_from_store_using_join,
    )?;

    cx.export_function("panicPreAwait", panic_pre_await)?;
    cx.export_function("panicDuringCallback", panic_during_callback)?;
    cx.export_function("panicPostAwait", panic_post_await)?;
    cx.export_function("panicDuringSettle", panic_during_settle)?;

    cx.export_function("throwPreAwait", throw_pre_await)?;
    cx.export_function("throwDuringCallback", throw_during_callback)?;
    cx.export_function("throwPostAwait", throw_post_await)?;
    cx.export_function("throwDuringSettle", throw_during_settle)?;

    Ok(())
}
