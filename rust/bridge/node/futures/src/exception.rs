//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use neon::prelude::*;

/// Private implementation for [PersistentException].
///
/// This is a separate type to avoid exposing the cases to clients.
enum PersistentExceptionValue {
    Object(Root<JsObject>),
    String(String),
}

/// Persists a JavaScript exception across call contexts for later re-throwing
/// (or promise rejection).
///
/// Like [neon::handle::Root][root], but falls back to preserving a string representation
/// if the wrapped value is not a JavaScript Object.
///
/// PersistentException *must* be consumed explicitly using [drop][PersistentException::drop]
/// or [into_inner][PersistentException::into_inner], like Root.
/// This is because it must be unregistered with the JavaScript garbage collector.
///
/// [root]: https://docs.rs/neon/0.9.0/neon/handle/struct.Root.html
pub struct PersistentException {
    wrapped: PersistentExceptionValue,
}

impl PersistentException {
    /// Persists `value` until the result is dropped.
    ///
    /// If `value` is not a JavaScript Object, it will be converted to a string instead.
    pub fn new<'a, V: Value>(cx: &mut impl Context<'a>, value: Handle<'a, V>) -> Self {
        let wrapped = match value.downcast::<JsObject, _>(cx) {
            Ok(object) => PersistentExceptionValue::Object(object.root(cx)),
            Err(_) => PersistentExceptionValue::String(
                value
                    .to_string(cx)
                    .expect("Exception can be converted to string")
                    .value(cx),
            ),
        };
        Self { wrapped }
    }

    /// Produces the referenced JavaScript value, allowing it to be garbage collected.
    ///
    /// If the wrapped value was converted to a string, a JavaScript string will be produced instead.
    pub fn into_inner<'a>(self, cx: &mut impl Context<'a>) -> Handle<'a, JsValue> {
        match self.wrapped {
            PersistentExceptionValue::Object(root) => root.into_inner(cx).upcast(),
            PersistentExceptionValue::String(message) => cx.string(message).upcast(),
        }
    }

    /// Produces the referenced JavaScript object without consuming `self`.
    ///
    /// If the wrapped value was converted to a string, a JavaScript string will be produced.
    pub fn to_inner<'a>(&self, cx: &mut impl Context<'a>) -> Handle<'a, JsValue> {
        match &self.wrapped {
            PersistentExceptionValue::Object(root) => root.to_inner(cx).upcast(),
            PersistentExceptionValue::String(message) => cx.string(message).upcast(),
        }
    }

    /// Consumes `self`, allowing the wrapped value to be garbage collected.
    pub fn drop<'a>(self, cx: &mut impl Context<'a>) {
        self.finalize(cx)
    }
}

impl Finalize for PersistentException {
    fn finalize<'a, C: Context<'a>>(self, cx: &mut C) {
        if let PersistentExceptionValue::Object(root) = self.wrapped {
            root.finalize(cx)
        }
    }
}
