//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol::*;
use std::convert::TryFrom;
use std::ops::Deref;

pub(crate) use neon::context::Context;
pub(crate) use neon::prelude::*;

/// Used to keep track of all generated entry points.
///
/// Takes the *JavaScript* name `fooBar` of a function; the corresponding Rust function must be
/// declared `node_fooBar`.
// Declared early so it can be used in submodules.
macro_rules! node_register {
    ( $name:ident ) => {
        paste! {
            #[no_mangle] // necessary because we are linking as a cdylib
            #[allow(non_upper_case_globals)]
            #[linkme::distributed_slice(crate::node::LIBSIGNAL_FNS)]
            static [<signal_register_node_ $name>]: (&str, crate::node::JsFn) =
                (stringify!($name), [<node_ $name>]);
        }
    };
}

#[macro_use]
mod convert;
pub use convert::*;

mod error;
pub use error::*;

mod storage;
pub use storage::*;

/// A function pointer referring to a Neon-based Node entry point.
#[doc(hidden)]
pub(crate) type JsFn = for<'a> fn(FunctionContext<'a>) -> JsResult<'a, JsValue>;

#[doc(hidden)]
#[linkme::distributed_slice]
pub(crate) static LIBSIGNAL_FNS: [(&'static str, JsFn)] = [..];

/// Exports all `bridge_fn`-generated entry points.
pub fn register(cx: &mut ModuleContext) -> NeonResult<()> {
    for (name, f) in LIBSIGNAL_FNS {
        cx.export_function(name, *f)?;
    }
    Ok(())
}

/// A wrapper around a type that implements Neon's [`Finalize`] by simply dropping the type.
pub struct DefaultFinalize<T>(pub T);

impl<T> Finalize for DefaultFinalize<T> {}

impl<T> Deref for DefaultFinalize<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::borrow::Borrow<T> for DefaultFinalize<T> {
    fn borrow(&self) -> &T {
        &self.0
    }
}

pub type DefaultJsBox<T> = JsBox<DefaultFinalize<T>>;

pub fn return_boxed_object<'a, T: 'static + Send>(
    cx: &mut impl Context<'a>,
    value: Result<T, SignalProtocolError>,
) -> JsResult<'a, JsValue> {
    match value {
        Ok(v) => Ok(cx.boxed(DefaultFinalize(v)).upcast()),
        Err(e) => cx.throw_error(e.to_string()),
    }
}

pub fn return_binary_data<'a, T: AsRef<[u8]>>(
    cx: &mut impl Context<'a>,
    bytes: Result<Option<T>, SignalProtocolError>,
) -> JsResult<'a, JsValue> {
    match bytes {
        Ok(Some(bytes)) => {
            let bytes = bytes.as_ref();

            let bytes_len = match u32::try_from(bytes.len()) {
                Ok(l) => l,
                Err(_) => {
                    return cx.throw_error("Cannot return very large object to JS environment")
                }
            };
            let mut buffer = cx.buffer(bytes_len)?;
            cx.borrow_mut(&mut buffer, |raw_buffer| {
                raw_buffer.as_mut_slice().copy_from_slice(&bytes);
            });
            Ok(buffer.upcast())
        }
        Ok(None) => Ok(cx.null().upcast()),
        Err(e) => cx.throw_error(e.to_string()),
    }
}

pub fn return_string<'a, T: AsRef<str>>(
    cx: &mut FunctionContext<'a>,
    string: Result<Option<T>, SignalProtocolError>,
) -> JsResult<'a, JsValue> {
    match string {
        Ok(Some(string)) => Ok(cx.string(string).upcast()),
        Ok(None) => Ok(cx.null().upcast()),
        Err(e) => cx.throw_error(e.to_string()),
    }
}

pub(crate) fn with_buffer_contents<R>(
    cx: &mut FunctionContext,
    buffer: Handle<JsBuffer>,
    f: impl for<'a> FnOnce(&'a [u8]) -> R,
) -> R {
    let guard = cx.lock();
    let slice = buffer.borrow(&guard).as_slice::<u8>();
    f(slice)
}

/// Implementation of [`bridge_deserialize`](crate::support::bridge_deserialize) for Node.
macro_rules! node_bridge_deserialize {
    ( $typ:ident::$fn:path as false ) => {};
    ( $typ:ident::$fn:path as $node_name:ident ) => {
        paste! {
            #[allow(non_snake_case, clippy::redundant_closure)]
            #[doc = "ts: export function " $node_name "_Deserialize(buffer: Buffer): " $typ]
            pub fn [<node_ $node_name _Deserialize>](
                mut cx: node::FunctionContext
            ) -> node::JsResult<node::JsValue> {
                let buffer = cx.argument::<node::JsBuffer>(0)?;
                let obj: Result<$typ> =
                    node::with_buffer_contents(&mut cx, buffer, |buf| $typ::$fn(buf));
                match obj {
                    Ok(obj) => node::ResultTypeInfo::convert_into(obj, &mut cx),
                    Err(err) => {
                        let module = cx.this();
                        node::SignalNodeError::throw(
                            err,
                            &mut cx,
                            module,
                            stringify!([<$node_name "_Deserialize">]))
                    }
                }
            }

            node_register!([<$node_name _Deserialize>]);
        }
    };
    ( $typ:ident::$fn:path ) => {
        node_bridge_deserialize!($typ::$fn as $typ);
    };
}
