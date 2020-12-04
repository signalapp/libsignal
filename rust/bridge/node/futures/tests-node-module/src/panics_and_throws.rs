//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use neon::prelude::*;
use signal_neon_futures::*;

#[allow(unreachable_code, unused_variables)]
pub fn panic_pre_await(mut cx: FunctionContext) -> JsResult<JsObject> {
    let promise = cx.argument::<JsObject>(0)?;

    let future = JsFuture::await_promise(&mut cx, promise, move |cx, result| {
        PersistentException::try_catch(cx, |cx| {
            let value = result.or_else(|e| cx.throw(e))?;
            Ok(value.downcast_or_throw::<JsNumber, _>(cx)?.value(cx))
        })
    })?;

    signal_neon_futures::promise(&mut cx, async move {
        panic!("check for this");
        future.await?;
        fulfill_promise(move |cx| Ok(cx.undefined()))
    })
}

#[allow(unreachable_code)]
pub fn panic_during_callback(mut cx: FunctionContext) -> JsResult<JsObject> {
    let promise = cx.argument::<JsObject>(0)?;

    let future = JsFuture::await_promise(&mut cx, promise, move |_cx, _result| {
        panic!("check for this");
    })?;

    signal_neon_futures::promise(&mut cx, async move {
        future.await;
        fulfill_promise(move |cx| Ok(cx.undefined()))
    })
}

#[allow(unreachable_code)]
pub fn panic_post_await(mut cx: FunctionContext) -> JsResult<JsObject> {
    let promise = cx.argument::<JsObject>(0)?;

    let future = JsFuture::await_promise(&mut cx, promise, move |cx, result| {
        PersistentException::try_catch(cx, |cx| {
            let value = result.or_else(|e| cx.throw(e))?;
            Ok(value.downcast_or_throw::<JsNumber, _>(cx)?.value(cx))
        })
    })?;

    signal_neon_futures::promise(&mut cx, async move {
        future.await?;
        panic!("check for this");
        fulfill_promise(move |cx| Ok(cx.undefined()))
    })
}

#[allow(unreachable_code, unused_variables)]
pub fn panic_during_fulfill(mut cx: FunctionContext) -> JsResult<JsObject> {
    let promise = cx.argument::<JsObject>(0)?;

    let future = JsFuture::await_promise(&mut cx, promise, move |cx, result| {
        PersistentException::try_catch(cx, |cx| {
            let value = result.or_else(|e| cx.throw(e))?;
            Ok(value.downcast_or_throw::<JsNumber, _>(cx)?.value(cx))
        })
    })?;

    signal_neon_futures::promise(&mut cx, async move {
        future.await?;
        fulfill_promise(move |cx| {
            panic!("check for this");
            Ok(cx.undefined())
        })
    })
}

#[allow(unreachable_code, unused_variables)]
pub fn throw_pre_await(mut cx: FunctionContext) -> JsResult<JsObject> {
    let promise = cx.argument::<JsObject>(0)?;

    let future = JsFuture::await_promise(&mut cx, promise, move |cx, result| {
        PersistentException::try_catch(cx, |cx| {
            let value = result.or_else(|e| cx.throw(e))?;
            Ok(value.downcast_or_throw::<JsNumber, _>(cx)?.value(cx))
        })
    })?;

    let error = cx.error("check for this")?;
    let persistent_error = PersistentException::new(&mut cx, error);

    signal_neon_futures::promise(&mut cx, async move {
        return Err(persistent_error);
        future.await?;
        fulfill_promise(move |cx| Ok(cx.undefined()))
    })
}

pub fn throw_during_callback(mut cx: FunctionContext) -> JsResult<JsObject> {
    let promise = cx.argument::<JsObject>(0)?;

    let future = JsFuture::await_promise(&mut cx, promise, move |cx, _result| {
        PersistentException::try_catch(cx, |cx| {
            cx.throw_error("check for this")?;
            Ok(())
        })
    })?;

    signal_neon_futures::promise(&mut cx, async move {
        future.await?;
        fulfill_promise(move |cx| Ok(cx.undefined()))
    })
}

#[allow(unreachable_code)]
pub fn throw_post_await(mut cx: FunctionContext) -> JsResult<JsObject> {
    let promise = cx.argument::<JsObject>(0)?;

    let future = JsFuture::await_promise(&mut cx, promise, move |cx, result| {
        PersistentException::try_catch(cx, |cx| {
            let value = result.or_else(|e| cx.throw(e))?;
            Ok(value.downcast_or_throw::<JsNumber, _>(cx)?.value(cx))
        })
    })?;

    let error = cx.error("check for this")?;
    let persistent_error = PersistentException::new(&mut cx, error);

    signal_neon_futures::promise(&mut cx, async move {
        future.await?;
        return Err(persistent_error);
        fulfill_promise(move |cx| Ok(cx.undefined()))
    })
}

pub fn throw_during_fulfill(mut cx: FunctionContext) -> JsResult<JsObject> {
    let promise = cx.argument::<JsObject>(0)?;

    let future = JsFuture::await_promise(&mut cx, promise, move |cx, result| {
        PersistentException::try_catch(cx, |cx| {
            let value = result.or_else(|e| cx.throw(e))?;
            Ok(value.downcast_or_throw::<JsNumber, _>(cx)?.value(cx))
        })
    })?;

    signal_neon_futures::promise(&mut cx, async move {
        future.await?;
        fulfill_promise(move |cx| {
            cx.throw_error("check for this")?;
            Ok(cx.undefined())
        })
    })
}
