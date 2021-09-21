//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use neon::prelude::*;
use std::any::Any;

// See https://github.com/rust-lang/rfcs/issues/1389
pub(crate) fn describe_panic(any: &Box<dyn Any + Send>) -> String {
    if let Some(msg) = any.downcast_ref::<&str>() {
        msg.to_string()
    } else if let Some(msg) = any.downcast_ref::<String>() {
        msg.to_string()
    } else {
        "(break on rust_panic to debug)".to_string()
    }
}

/// A convenience for calling a method on an object.
///
/// Equivalent to calling `get`, downcasting to a function, and then using `call`.
pub fn call_method<'a>(
    cx: &mut impl Context<'a>,
    this: Handle<'a, impl Object>,
    method_name: &str,
    args: impl AsRef<[Handle<'a, JsValue>]>,
) -> JsResult<'a, JsValue> {
    let method: Handle<JsFunction> = this.get(cx, method_name)?;
    method.call(cx, this, args)
}
