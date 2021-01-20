//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol_rust::*;
use neon::context::Context;
use std::ops::Deref;

pub use neon::prelude::*;

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

pub(crate) fn with_buffer_contents<R>(
    cx: &mut FunctionContext,
    buffer: Handle<JsBuffer>,
    f: impl for<'a> FnOnce(&'a [u8]) -> R,
) -> R {
    let guard = cx.lock();
    let slice = buffer.borrow(&guard).as_slice::<u8>();
    f(slice)
}

macro_rules! node_bridge_deserialize {
    ( $typ:ident::$fn:path as None ) => {};
    ( $typ:ident::$fn:path as $node_name:ident ) => {
        paste! {
            #[allow(non_snake_case, clippy::redundant_closure)]
            pub fn [<node_ $node_name _deserialize>](
                mut cx: node::FunctionContext
            ) -> node::JsResult<node::JsValue> {
                let buffer = cx.argument::<node::JsBuffer>(0)?;
                let obj: Result<$typ, _> =
                    node::with_buffer_contents(&mut cx, buffer, |buf| $typ::$fn(buf));
                node::return_boxed_object(&mut cx, obj)
            }
        }
    };
    ( $typ:ident::$fn:path ) => {
        node_bridge_deserialize!($typ::$fn as $typ);
    };
}
