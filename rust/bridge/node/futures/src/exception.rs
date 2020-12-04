//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use neon::prelude::*;

/// See [PersistentException]
enum PersistentExceptionImpl {
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
/// [root]: https://docs.rs/neon/0.7.0-napi.3/neon/handle/struct.Root.html
pub struct PersistentException {
    wrapped: PersistentExceptionImpl,
}

impl PersistentException {
    /// Persists `value` until the result is dropped.
    ///
    /// If `value` is not a JavaScript Object, it will be converted to a string instead.
    pub fn new<'a, V: Value>(cx: &mut impl Context<'a>, value: Handle<'a, V>) -> Self {
        use PersistentExceptionImpl as Impl;
        let wrapped = match value.downcast::<JsObject, _>(cx) {
            Ok(object) => Impl::Object(object.root(cx)),
            Err(_) => Impl::String(value.to_string(cx).unwrap().value(cx)),
        };
        Self { wrapped }
    }

    /// Runs `body`, wrapping any thrown exceptions using [new][PersistentException::new].
    pub fn try_catch<'a, C: Context<'a>, T>(
        cx: &mut C,
        body: impl FnOnce(&mut C) -> NeonResult<T>,
    ) -> Result<T, Self> {
        cx.try_catch(body).map_err(|e| Self::new(cx, e))
    }

    /// Produces the referenced JavaScript value, allowing it to be garbage collected.
    ///
    /// If the wrapped value was converted to a string, a JavaScript string will be produced instead.
    pub fn into_inner<'a>(self, cx: &mut impl Context<'a>) -> Handle<'a, JsValue> {
        use PersistentExceptionImpl as Impl;
        match self.wrapped {
            Impl::Object(root) => root.into_inner(cx).upcast(),
            Impl::String(message) => cx.string(message).upcast(),
        }
    }

    /// Produces the referenced JavaScript object without consuming `self`.
    ///
    /// If the wrapped value was converted to a string, a JavaScript string will be produced.
    pub fn to_inner<'a>(&self, cx: &mut impl Context<'a>) -> Handle<'a, JsValue> {
        use PersistentExceptionImpl as Impl;
        match &self.wrapped {
            Impl::Object(root) => root.to_inner(cx).upcast(),
            Impl::String(message) => cx.string(message).upcast(),
        }
    }

    /// Consumes `self` and throws the contained value, which will once again be eligible for garbage collection.
    ///
    /// If the wrapped value was converted to a string, a JavaScript string will be thrown.
    pub fn throw<'a>(self, cx: &mut impl Context<'a>) -> NeonResult<()> {
        let exception = self.into_inner(cx);
        cx.throw(exception)
    }

    /// Consumes `self`, allowing the wrapped value to be garbage collected.
    pub fn drop<'a>(self, cx: &mut impl Context<'a>) {
        self.finalize(cx)
    }
}

impl Finalize for PersistentException {
    fn finalize<'a, C: Context<'a>>(self, cx: &mut C) {
        use PersistentExceptionImpl as Impl;
        if let Impl::Object(root) = self.wrapped {
            root.finalize(cx)
        }
    }
}
