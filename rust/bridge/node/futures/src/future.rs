//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures::channel::oneshot;
use neon::prelude::*;
use std::future::Future;
use std::marker::PhantomData;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe, UnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use crate::result::*;
use crate::util::call_method;

mod builder;
pub use builder::JsFutureBuilder;

/// A future representing the result of a JavaScript promise.
///
/// JsFutures can be created with [from_promise](fn@JsFuture::from_promise) or [get_promise](fn@JsFuture::get_promise) and [JsFutureBuilder].
/// Once settled, a transformation callback is invoked in the current JavaScript context to produce a Rust value.
/// This is the result of `await`ing the future.
///
/// Panics in the transformation function will be propagated to the `await`ing context.
pub struct JsFuture<T: 'static + Send> {
    receiver: oneshot::Receiver<std::thread::Result<T>>,
}

impl<T: 'static + Send> Future for JsFuture<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context) -> Poll<Self::Output> {
        // See https://doc.rust-lang.org/std/pin/index.html#projections-and-structural-pinning.
        let receiver = unsafe { self.map_unchecked_mut(|s| &mut s.receiver) };
        receiver.poll(cx).map(|result| match result {
            Ok(Ok(result)) => result,
            Ok(Err(panic_info)) => resume_unwind(panic_info),
            Err(_) => {
                panic!("Future re-awaited, or JavaScript promise dropped without being settled")
            }
        })
    }
}

// A caught panic will never leave JsFuture in an invalid state;
// either it's received the result already or it hasn't.
impl<T: 'static + Send> UnwindSafe for JsFuture<T> {}

/// A type describing how to settle a [JsFuture].
///
/// Settling a future with the result of a JavaScript promise requires
/// 1. running the given transform synchronously to convert from a JavaScript type to a Rust type
/// 2. forwarding the result of that (or a panic) to the waiting Rust Future.
struct FutureSettler<T: Send + 'static> {
    sender: oneshot::Sender<std::thread::Result<T>>,

    #[allow(clippy::type_complexity)]
    transform: Box<
        dyn for<'a> FnOnce(&mut FunctionContext<'a>, JsPromiseResult<'a>) -> T + 'static + Send,
    >,
}

/// Represents a shared reference to a [FutureSettler].
///
/// Exactly one callback (from JavaScript) will be able to actually settle the future.
// FIXME: `Mutex<Option<X>>` is heavy for "a value that can atomically only be consumed once".
type FutureSettlerRef<T> = Arc<Mutex<Option<FutureSettler<T>>>>;

impl<T: Send + 'static> FutureSettler<T> {
    fn new_shared<F>(
        sender: oneshot::Sender<std::thread::Result<T>>,
        transform: F,
    ) -> FutureSettlerRef<T>
    where
        F: for<'a> FnOnce(&mut FunctionContext<'a>, JsPromiseResult<'a>) -> T + 'static + Send,
    {
        Arc::new(Mutex::new(Some(Self {
            sender,
            transform: Box::new(transform),
        })))
    }

    /// Produces a JavaScript function value representing [settle_promise]
    /// with the first argument bound to the given sender.
    fn bind_settle_promise<'a, C: Context<'a>, R: JsPromiseResultConstructor>(
        self_ref: FutureSettlerRef<T>,
        cx: &mut C,
    ) -> JsResult<'a, JsValue> {
        let settle = JsFunction::new(cx, settle_promise::<T, R>)?;
        let bind_args = vec![cx.undefined().upcast(), cx.boxed(self_ref).upcast()];
        call_method(cx, settle, "bind", bind_args)
    }
}

impl<T: Send> Finalize for FutureSettler<T> {}

/// Registered as the callback for the `resolve` and `reject` parameters of [`Promise.then`][then].
///
/// This callback assumes its first (bound) argument represents a boxed [FutureSettlerRef].
/// If the future has not already been settled, it is settled now and the future will be awoken.
///
/// [then]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/then
fn settle_promise<T: Send + 'static, R: JsPromiseResultConstructor>(
    mut cx: FunctionContext,
) -> JsResult<JsUndefined> {
    let shared_future_settler = cx.argument::<JsBox<FutureSettlerRef<T>>>(0)?;
    let js_result = cx.argument(1)?;

    if let Some(future_settler) = shared_future_settler
        .lock()
        .expect("Lock can be taken")
        .take()
    {
        let cx = &mut cx;
        let transform = future_settler.transform;
        let result = catch_unwind(AssertUnwindSafe(move || transform(cx, R::make(js_result))));
        let _ = future_settler.sender.send(result);
    } else {
        cx.throw_error("promise settled twice")?;
    }

    Ok(cx.undefined())
}

impl<T: 'static + Send> JsFuture<T> {
    /// Creates a new JsFuture by calling the JavaScript method [`then`][then] on `promise`.
    ///
    /// When settled, `transform` will be invoked in the new JavaScript context to produce the result of the Rust future.
    ///
    /// [then]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/then
    pub fn from_promise<'a, F>(
        cx: &mut impl Context<'a>,
        promise: Handle<'a, JsObject>,
        transform: F,
    ) -> NeonResult<Self>
    where
        F: for<'b> FnOnce(&mut FunctionContext<'b>, JsPromiseResult<'b>) -> T + 'static + Send,
    {
        let (sender, receiver) = oneshot::channel();
        let future_settler = FutureSettler::new_shared(sender, transform);

        let bound_fulfill =
            FutureSettler::bind_settle_promise::<_, JsFulfilledResult>(future_settler.clone(), cx)?;
        let bound_reject =
            FutureSettler::bind_settle_promise::<_, JsRejectedResult>(future_settler, cx)?;

        call_method(cx, promise, "then", vec![bound_fulfill, bound_reject])?;

        Ok(JsFuture { receiver })
    }

    /// Creates a new JsFuture by calling the JavaScript method [`then`][then] on the result of `get_promise`.
    ///
    /// `get_promise` will be run on the given EventQueue.
    /// The future will not be ready until it is given a result `transform`. See [JsFutureBuilder].
    ///
    /// [then]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/then
    pub fn get_promise<F>(queue: &EventQueue, get_promise: F) -> JsFutureBuilder<F, T>
    where
        F: for<'a> FnOnce(&mut TaskContext<'a>) -> JsResult<'a, JsObject> + Send + 'static,
    {
        JsFutureBuilder {
            queue,
            get_promise,
            result_type: PhantomData,
        }
    }
}
