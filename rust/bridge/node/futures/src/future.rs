//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use neon::prelude::*;
use std::future::Future;
use std::marker::PhantomData;
use std::mem;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::{Arc, Mutex, Weak};
use std::task::{Poll, Waker};

use crate::result::*;

mod builder;
pub use builder::JsFutureBuilder;

/// A transformation to convert a scoped JavaScript result (fulfillment or rejection) to an unscoped Rust result.
trait JsFutureCallback<T> =
    for<'a> FnOnce(&mut FunctionContext<'a>, JsPromiseResult<'a>) -> T + 'static + Send;

/// The possible states of a [JsFuture].
enum JsFutureState<T> {
    /// The future is waiting for resolution.
    Waiting {
        transform: Box<dyn JsFutureCallback<T>>,
        waker: Option<Waker>,
    },
    /// The future has been resolved (and transformed).
    ///
    /// If there was a panic during that transform, it will be caught and resumed at the `await` point.
    Complete(std::thread::Result<T>),
    /// The result has been returned from `poll`.
    Consumed,
}

impl<T> JsFutureState<T> {
    fn new(transform: impl JsFutureCallback<T>) -> Self {
        Self::Waiting {
            transform: Box::new(transform),
            waker: None,
        }
    }

    fn waiting_on(mut self, new_waker: Waker) -> Self {
        if let Self::Waiting { ref mut waker, .. } = self {
            *waker = Some(new_waker)
        } else {
            panic!("already completed")
        }
        self
    }
}

/// A future representing the result of a JavaScript promise.
///
/// JsFutures can be created with [await_promise](fn@JsFuture::await_promise) or [get_promise](fn@JsFuture::get_promise) and [JsFutureBuilder].
/// Once resolved, a transformation callback is invoked in the current JavaScript context to produce a Rust value.
/// This is the result of `await`ing the future.
///
/// Panics in the transformation function will be propagated to the `await`ing context.
pub struct JsFuture<T: 'static + Send> {
    // In practice there will only be one strong reference to one of these from Rust,
    // and two weak ones from JavaScript (for `resolve` and `reject`).
    shared: Arc<Mutex<JsFutureState<T>>>,
}

impl<T: 'static + Send> Future for JsFuture<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context) -> Poll<Self::Output> {
        let mut state_guard = self.shared.lock().unwrap();
        let state = mem::replace(&mut *state_guard, JsFutureState::Consumed);
        match state {
            JsFutureState::Complete(Ok(result)) => return Poll::Ready(result),
            JsFutureState::Complete(Err(panic)) => resume_unwind(panic),
            JsFutureState::Consumed => panic!("already consumed"),
            JsFutureState::Waiting { .. } => {}
        }
        *state_guard = state.waiting_on(cx.waker().clone());
        Poll::Pending
    }
}

struct WeakFutureToken<T: Send + 'static>(Weak<Mutex<JsFutureState<T>>>);

impl<T: Send + 'static> WeakFutureToken<T> {
    /// Creates a token referencing `future`.
    fn new(future: &JsFuture<T>) -> Self {
        Self(Arc::downgrade(&future.shared))
    }

    /// Produces a JavaScript function value representing [fulfill_promise]
    /// with the first argument bound to this token, boxed.
    fn bind_fulfill_promise<'a, C: Context<'a>, R: JsPromiseResultConstructor>(
        &self,
        cx: &mut C,
    ) -> JsResult<'a, JsValue> {
        let fulfill = JsFunction::new(cx, fulfill_promise::<T, R>)?;
        let bind = fulfill
            .get(cx, "bind")?
            .downcast_or_throw::<JsFunction, _>(cx)?;
        let bind_args = vec![
            cx.undefined().upcast::<JsValue>(),
            cx.boxed(self.clone()).upcast(),
        ];
        bind.call(cx, fulfill, bind_args)
    }
}

impl<T: Send> Finalize for WeakFutureToken<T> {}

impl<T: Send> Clone for WeakFutureToken<T> {
    fn clone(&self) -> Self {
        Self(Weak::clone(&self.0))
    }
}

/// Registered as the callback for the `resolve` and `reject` parameters of [`Promise.then`][then].
///
/// This callback assumes its first (bound) argument represents a boxed [WeakFutureToken].
/// If the referenced [JsFutureState] is still alive, it is fulfilled and the future awoken.
///
/// [then]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/then
fn fulfill_promise<T: Send + 'static, R: JsPromiseResultConstructor>(
    mut cx: FunctionContext,
) -> JsResult<JsUndefined> {
    let js_result = cx.argument(1)?;
    let future = &cx.argument::<JsBox<WeakFutureToken<T>>>(0)?.0;

    if let Some(future) = future.upgrade() {
        let mut state_guard = future.lock().unwrap();
        let state = mem::replace(&mut *state_guard, JsFutureState::Consumed);

        if let JsFutureState::Waiting { transform, waker } = state {
            let cx = &mut cx;
            let result = catch_unwind(AssertUnwindSafe(move || transform(cx, R::make(js_result))));
            *state_guard = JsFutureState::Complete(result);
            // Drop the lock before waking a waker.
            mem::drop(state_guard);
            if let Some(waker) = waker {
                waker.wake()
            }
        } else {
            *state_guard = state;
            cx.throw_error("promise fulfilled twice")?;
        }
    }

    Ok(cx.undefined())
}

impl<T: 'static + Send> JsFuture<T> {
    fn new(transform: impl JsFutureCallback<T>) -> Self {
        Self {
            shared: Arc::new(Mutex::new(JsFutureState::new(transform))),
        }
    }

    /// Creates a new JsFuture by calling the JavaScript method [`then`][then] on `promise`.
    ///
    /// When resolved, `transform` will be invoked in the new JavaScript context to produce the result of the Rust future.
    ///
    /// [then]: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/then
    pub fn await_promise<'a, F>(
        cx: &mut impl Context<'a>,
        promise: Handle<'a, JsObject>,
        transform: F,
    ) -> NeonResult<Self>
    where
        F: for<'b> FnOnce(&mut FunctionContext<'b>, JsPromiseResult<'b>) -> T + 'static + Send,
    {
        let future = JsFuture::new(transform);
        let fulfillment_token = WeakFutureToken::new(&future);

        let bound_resolve = fulfillment_token.bind_fulfill_promise::<_, JsResolvedResult>(cx)?;
        let bound_reject = fulfillment_token.bind_fulfill_promise::<_, JsRejectedResult>(cx)?;

        let then = promise
            .get(cx, "then")?
            .downcast_or_throw::<JsFunction, _>(cx)?;
        then.call(cx, promise, vec![bound_resolve, bound_reject])?;

        Ok(future)
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
