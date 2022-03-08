//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use neon::prelude::*;

use crate::future::*;
use crate::PersistentException;

/// Sets up a [JsFuture] using a builder pattern. See [JsFuture::get_promise].
pub struct JsFutureBuilder<'a, F, T: 'static + Send>
where
    F: for<'b> FnOnce(&mut TaskContext<'b>) -> JsResult<'b, JsObject> + 'static + Send,
{
    pub(super) channel: &'a Channel,
    pub(super) get_promise: F,
    pub(super) result_type: PhantomData<fn() -> T>,
}

impl<F, T: 'static + Send> JsFutureBuilder<'_, F, T>
where
    F: for<'b> FnOnce(&mut TaskContext<'b>) -> JsResult<'b, JsObject> + 'static + Send,
{
    /// Produces a future using the given result handler.
    ///
    /// Note that if there was a JavaScript exception during the creation of this JsFutureBuilder,
    /// `transform` will be called **immediately** to produce a result,
    /// treating the exception as a promise rejection.
    pub fn then<XF>(self, transform: XF) -> JsFuture<T>
    where
        XF: for<'b> FnOnce(&mut FunctionContext<'b>, JsPromiseResult<'b>) -> T + 'static + Send,
    {
        let future = JsFuture::new(transform);
        let settle_token = WeakFutureToken::new(&future);
        let get_promise = self.get_promise;

        self.channel.send(move |mut cx| {
            let mut maybe_bound_reject = None;
            let result = cx.try_catch(|cx| {
                let bound_reject = settle_token.bind_settle_promise::<_, JsRejectedResult>(cx)?;
                maybe_bound_reject = Some(bound_reject);

                let bound_fulfill = settle_token.bind_settle_promise::<_, JsFulfilledResult>(cx)?;

                let promise = get_promise(cx)?;
                call_method(cx, promise, "then", [bound_fulfill, bound_reject])?;

                Ok(())
            });
            if let Err(exception) = result {
                if let Some(bound_reject) = maybe_bound_reject {
                    let undef = cx.undefined();
                    bound_reject
                        .downcast_or_throw::<JsFunction, _>(&mut cx)?
                        .call(&mut cx, undef, [exception])?;
                } else {
                    cx.throw(exception)?;
                }
            }
            Ok(())
        });

        future
    }
}

impl<F, T: 'static + Send> JsFutureBuilder<'_, F, Result<T, PersistentException>>
where
    F: for<'b> FnOnce(&mut TaskContext<'b>) -> JsResult<'b, JsObject> + 'static + Send,
{
    /// Produces a future that records failures as PersistentExceptions.
    ///
    /// This is a convenience to allow the result handler to throw JavaScript exceptions using NeonResult.
    /// Note that this does *not* automatically treat incoming rejections as failures; if that is desired,
    /// it can be accomplished using `result.or_else(|e| cx.throw(e))?;` in the body of `transform`.
    pub fn then_try<XF>(self, transform: XF) -> JsFuture<Result<T, PersistentException>>
    where
        XF: for<'b> FnOnce(&mut FunctionContext<'b>, JsPromiseResult<'b>) -> NeonResult<T>
            + 'static
            + Send,
    {
        self.then(move |cx, result| {
            cx.try_catch(|cx| transform(cx, result))
                .map_err(|e| PersistentException::new(cx, e))
        })
    }
}
