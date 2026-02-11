//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::Arc;

use libsignal_protocol::*;
pub use neon::context::Context;
pub use neon::prelude::*;
pub use neon::types::buffer::TypedArray;
pub use signal_neon_futures::call_method;
use signal_neon_futures::{JsFuture, JsPromiseResult};

/// Used to keep track of all generated entry points.
///
/// Takes the *JavaScript* name `fooBar` of a function; the corresponding Rust function must be
/// declared `node_fooBar`.
// Declared early so it can be used in submodules.
#[macro_export]
macro_rules! node_register {
    ( $name:ident ) => {
        ::paste::paste! {
            #[unsafe(no_mangle)] // necessary because we are linking as a cdylib
            #[allow(non_upper_case_globals)]
            #[linkme::distributed_slice($crate::node::LIBSIGNAL_FNS)]
            static [<signal_register_node_ $name>]: (&str, $crate::node::JsFn) =
                (stringify!($name), [<node_ $name>]);
        }
    };
}

#[macro_use]
mod convert;
pub use convert::*;

mod error;
pub use error::*;

mod futures;
pub use futures::*;

mod io;
pub use io::*;

mod chat;
mod storage;

pub use storage::*;

use crate::support::WithContext;

/// A function pointer referring to a Neon-based Node entry point.
#[doc(hidden)]
pub type JsFn = for<'a> fn(FunctionContext<'a>) -> JsResult<'a, JsValue>;

#[doc(hidden)]
#[linkme::distributed_slice]
pub static LIBSIGNAL_FNS: [(&'static str, JsFn)] = [..];

/// Exports all `bridge_fn`-generated entry points.
pub fn register(cx: &mut ModuleContext) -> NeonResult<()> {
    for (name, f) in LIBSIGNAL_FNS {
        cx.export_function(name, *f)?;
    }
    Ok(())
}

/// A wrapper around a type that implements Neon's [`Finalize`] by simply dropping the type.
#[derive(derive_more::Deref, derive_more::From)]
pub struct DefaultFinalize<T>(pub T);

impl<T> Finalize for DefaultFinalize<T> {}

pub type DefaultJsBox<T> = JsBox<DefaultFinalize<T>>;

/// A standard idiom for a callback object usable from any thread, used by `bridge_callbacks`.
pub struct RootAndChannel {
    js_channel: Channel,
    // Root can only be cloned within a Context, but we need to rehydrate it every time we do a
    // callback. Wrapping it in Arc is the easiest solution.
    root: Arc<Root<JsObject>>,
}

impl RootAndChannel {
    pub fn new(cx: &mut FunctionContext, callbacks: Handle<JsObject>) -> NeonResult<Self> {
        let mut channel = cx.channel();
        channel.unref(cx);

        Ok(Self {
            js_channel: channel,
            root: Arc::new(callbacks.root(cx)),
        })
    }

    /// Scaffolding to invoke a callback on the object owned by `self`, and return a Future for its
    /// result.
    ///
    /// Concretely, `operation` will be sent to the JavaScript thread, and is expected to produce a
    /// JavaScript Promise. A resolved promise will convert the result back to Rust using
    /// [`CallbackResultTypeInfo`]; a rejected promise will stringify the error and convert it to the
    /// error type of the caller's choice.
    ///
    /// Used by [`bridge_callbacks`](libsignal_bridge_macros::bridge_callbacks), but can be invoked
    /// directly as well.
    pub fn get_promise<F, T, E>(&self, name: &'static str, operation: F) -> JsFuture<Result<T, E>>
    where
        F: for<'a> FnOnce(&mut Cx<'a>, Handle<'a, JsObject>) -> NeonResult<Handle<'a, JsObject>>
            + Send
            + 'static,
        T: CallbackResultTypeInfo + Send + 'static,
        E: From<WithContext<String>> + Send,
    {
        /// Generates a closure to convert the promise's result type back to Rust.
        ///
        /// This is a separate function to keep it from being instantiated as many times as
        /// `get_promise`, which will have a unique instantiation for every callback.
        ///
        /// Skip past this function to see the implementation of `get_promise`.
        fn handle_result<T, E>(
            name: &'static str,
        ) -> impl for<'a> FnOnce(&mut FunctionContext<'a>, JsPromiseResult<'a>) -> Result<T, E>
        where
            T: CallbackResultTypeInfo,
            E: From<WithContext<String>>,
        {
            move |cx, result| {
                result
                    .and_then(|value| {
                        cx.try_catch(|cx| {
                            let value = value.downcast_or_throw(cx)?;
                            T::convert_from_callback(cx, value)
                        })
                    })
                    .map_err(|error| {
                        let description = error.to_string(cx).map(|s| s.value(cx)).unwrap_or_else(
                            |_: neon::result::Throw| "<unknown JavaScript error>".into(),
                        );
                        WithContext {
                            operation: name,
                            inner: description,
                        }
                        .into()
                    })
            }
        }

        let root = self.root.clone();
        JsFuture::get_promise(&self.js_channel, move |cx| {
            let object = root.to_inner(cx);
            let result = operation(cx, object);
            root.finalize(cx);
            result
        })
        .then(handle_result(name))
    }

    /// Runs an operation on the JavaScript thread, with the object owned by `self` available for
    /// use.
    ///
    /// This is a "fire and forget" operation; it does not complete synchronously, and it will not
    /// do anything but log error results.
    pub fn send_and_log_on_error<F>(&self, name: &'static str, operation: F)
    where
        F: for<'a> FnOnce(&mut Cx<'a>, Handle<'a, JsObject>) -> NeonResult<()> + Send + 'static,
    {
        let root = self.root.clone();
        self.js_channel.send(move |mut cx| {
            cx.try_catch(move |cx| {
                let object = root.to_inner(cx);
                let result = operation(cx, object);
                root.finalize(cx);
                result
            })
            .unwrap_or_else(|e| {
                log::error!(
                    "failed to report {name}: {}",
                    e.to_string(&mut cx)
                        .map(|msg| msg.value(&mut cx))
                        .as_deref()
                        .unwrap_or("<unable to print error>")
                )
            });
            Ok(())
        });
    }
}

impl Finalize for RootAndChannel {
    fn finalize<'a, C: Context<'a>>(self, cx: &mut C) {
        let Self {
            js_channel: _,
            root,
        } = self;
        root.finalize(cx);
    }
}
