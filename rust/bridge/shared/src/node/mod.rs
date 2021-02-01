//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol_rust::*;
use std::convert::TryFrom;
use std::ops::Deref;

pub use neon::context::{Context, Lock};
pub use neon::prelude::*;

#[macro_use]
mod convert;
pub use convert::SimpleArgTypeInfo;
pub(crate) use convert::*;

pub type JsFn = for<'a> fn(FunctionContext<'a>) -> JsResult<'a, JsValue>;

#[linkme::distributed_slice]
pub(crate) static LIBSIGNAL_FNS: [(&'static str, JsFn)] = [..];

pub fn register(cx: &mut ModuleContext) -> NeonResult<()> {
    for (name, f) in LIBSIGNAL_FNS {
        cx.export_function(name, *f)?;
    }
    Ok(())
}

pub struct DefaultFinalize<T>(T);

impl<T> Finalize for DefaultFinalize<T> {}

impl<T> Deref for DefaultFinalize<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub type DefaultJsBox<T> = JsBox<DefaultFinalize<T>>;

pub fn return_boxed_object<'a, T: 'static + Send>(
    cx: &mut FunctionContext<'a>,
    value: Result<T, SignalProtocolError>,
) -> JsResult<'a, JsValue> {
    match value {
        Ok(v) => Ok(cx.boxed(DefaultFinalize(v)).upcast()),
        Err(e) => cx.throw_error(e.to_string()),
    }
}

pub fn return_binary_data<'a, T: AsRef<[u8]>>(
    cx: &mut FunctionContext<'a>,
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

pub fn return_number<'a>(
    cx: &mut FunctionContext<'a>,
    value: Result<u32, SignalProtocolError>,
) -> JsResult<'a, JsValue> {
    match value {
        Ok(n) => Ok(JsNumber::new(cx, n).upcast()),
        Err(e) => cx.throw_error(e.to_string()),
    }
}

/*
pub fn return_optional_number<'a>(cx: &mut FunctionContext<'a>,
                              value: Result<Option<u32>, SignalProtocolError>) -> JsResult<'a, JsValue> {
    match value {
        Ok(Some(n)) => Ok(JsValue::from(n)),
        Ok(None) => Ok(cx.null().upcast()),
        Err(e) => cx.throw_error(e.to_string()),
    }
}
*/

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

macro_rules! node_register {
    ( $name:ident ) => {
        paste! {
            #[no_mangle] // necessary because we are linking as a cdylib
            #[allow(non_upper_case_globals)]
            #[linkme::distributed_slice(node::LIBSIGNAL_FNS)]
            static [<signal_register_node_ $name>]: (&str, node::JsFn) =
                (stringify!($name), [<node_ $name>]);
        }
    };
}

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
                let obj: Result<$typ, _> =
                    node::with_buffer_contents(&mut cx, buffer, |buf| $typ::$fn(buf));
                node::return_boxed_object(&mut cx, obj)
            }

            node_register!([<$node_name _Deserialize>]);
        }
    };
    ( $typ:ident::$fn:path ) => {
        node_bridge_deserialize!($typ::$fn as $typ);
    };
}

macro_rules! node_bridge_get_bytearray {
    ( $name:ident($typ:ty) as false => $body:expr ) => {};
    ( $name:ident($typ:ty) as $node_name:tt => $body:expr ) => {
        paste! {
            #[allow(non_snake_case)]
            #[doc = "ts: export function " $node_name "(obj: " $typ "): Buffer"]
            pub fn [<node_ $node_name>](
                mut cx: node::FunctionContext
            ) -> node::JsResult<node::JsValue> {
                expr_as_fn!(inner_get<'a>(
                    obj: &'a $typ
                ) -> Result<impl AsRef<[u8]> + 'a, SignalProtocolError> => $body);
                let obj = cx.argument::<node::DefaultJsBox<$typ>>(0)?;
                let bytes = inner_get(&obj);
                node::return_binary_data(&mut cx, bytes.map(Some))
            }

            node_register!($node_name);
        }
    };
    ( $name:ident($typ:ty) => $body:expr ) => {
        paste! {
            node_bridge_get_bytearray!($name($typ) as [<$typ _ $name:camel>] => $body);
        }
    };
}

macro_rules! node_bridge_get_optional_bytearray {
    ( $name:ident($typ:ty) as false => $body:expr ) => {};
    ( $name:ident($typ:ty) as $node_name:tt => $body:expr ) => {
        paste! {
            #[allow(non_snake_case)]
            #[doc = "ts: export function " $node_name "(obj: " $typ "): Buffer | null"]
            pub fn [<node_ $node_name>](
                mut cx: node::FunctionContext
            ) -> node::JsResult<node::JsValue> {
                expr_as_fn!(inner_get<'a>(
                    obj: &'a $typ
                ) -> Result<Option<impl AsRef<[u8]> + 'a>, SignalProtocolError> => $body);
                let obj = cx.argument::<node::DefaultJsBox<$typ>>(0)?;
                let bytes = inner_get(&obj);
                node::return_binary_data(&mut cx, bytes)
            }

            node_register!($node_name);
        }
    };
    ( $name:ident($typ:ty) => $body:expr ) => {
        paste! {
            node_bridge_get_optional_bytearray!($name($typ) as [<$typ _ $name:camel>] => $body);
        }
    };
}

macro_rules! node_bridge_get_int {
    ( $name:ident($typ:ty) as false => $body:expr ) => {};
    ( $name:ident($typ:ty) as $node_name:tt => $body:expr ) => {
        paste! {
            #[allow(non_snake_case)]
            #[doc = "ts: export function " $node_name "(obj: " $typ "): number"]
            pub fn [<node_ $node_name>](
                mut cx: node::FunctionContext
            ) -> node::JsResult<node::JsValue> {
                expr_as_fn!(inner_get<'a>(
                    obj: &'a $typ
                ) -> Result<u32, SignalProtocolError> => $body);
                let obj = cx.argument::<node::DefaultJsBox<$typ>>(0)?;
                let number = inner_get(&obj);
                node::return_number(&mut cx, number)
            }

            node_register!($node_name);
        }
    };
    ( $name:ident($typ:ty) => $body:expr ) => {
        paste! {
            node_bridge_get_int!($name($typ) as [<$typ _ $name:camel>] => $body);
        }
    };
}
