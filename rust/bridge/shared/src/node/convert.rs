//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use neon::prelude::*;
use std::borrow::Cow;
use std::convert::{TryFrom, TryInto};
use std::ops::RangeInclusive;

pub trait ArgTypeInfo<'storage, 'context: 'storage>: Sized {
    type ArgType: neon::types::Value;
    type StoredType: 'storage;
    fn borrow(
        cx: &mut FunctionContext,
        foreign: Handle<'context, Self::ArgType>,
    ) -> NeonResult<Self::StoredType>;
    fn load_from(stored: &'storage mut Self::StoredType) -> Self;
}

pub trait SimpleArgTypeInfo: Sized + 'static {
    type ArgType: neon::types::Value;
    fn convert_from(cx: &mut FunctionContext, foreign: Handle<Self::ArgType>) -> NeonResult<Self>;
}

impl<'a, T> ArgTypeInfo<'a, 'a> for T
where
    T: SimpleArgTypeInfo,
{
    type ArgType = T::ArgType;
    type StoredType = Option<Self>;
    fn borrow(
        cx: &mut FunctionContext,
        foreign: Handle<'a, Self::ArgType>,
    ) -> NeonResult<Self::StoredType> {
        Ok(Some(Self::convert_from(cx, foreign)?))
    }
    fn load_from(stored: &'a mut Self::StoredType) -> Self {
        stored.take().expect("should only be loaded once")
    }
}

pub trait ResultTypeInfo<'a>: Sized {
    type ResultType: neon::types::Value;
    fn convert_into(self, cx: &mut impl Context<'a>) -> NeonResult<Handle<'a, Self::ResultType>>;
}

fn can_convert_js_number_to_int(value: f64, valid_range: RangeInclusive<f64>) -> bool {
    value.is_finite() && value.fract() == 0.0 && valid_range.contains(&value)
}

// 2**53 - 1, the maximum "safe" integer representable in an f64.
// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/MAX_SAFE_INTEGER
const MAX_SAFE_JS_INTEGER: f64 = 9007199254740991.0;

impl SimpleArgTypeInfo for u64 {
    type ArgType = JsNumber;
    fn convert_from(cx: &mut FunctionContext, foreign: Handle<Self::ArgType>) -> NeonResult<Self> {
        let value = foreign.value(cx);
        if !can_convert_js_number_to_int(value, 0.0..=MAX_SAFE_JS_INTEGER) {
            return cx.throw_range_error(format!("cannot convert {} to u64", value));
        }
        Ok(value as u64)
    }
}

impl SimpleArgTypeInfo for String {
    type ArgType = JsString;
    fn convert_from(cx: &mut FunctionContext, foreign: Handle<Self::ArgType>) -> NeonResult<Self> {
        Ok(foreign.value(cx))
    }
}

impl<'storage, 'context: 'storage, T> ArgTypeInfo<'storage, 'context> for Option<T>
where
    T: ArgTypeInfo<'storage, 'context>,
{
    type ArgType = JsValue;
    type StoredType = Option<T::StoredType>;
    fn borrow(
        cx: &mut FunctionContext,
        foreign: Handle<'context, Self::ArgType>,
    ) -> NeonResult<Self::StoredType> {
        if foreign.downcast::<JsNull, _>(cx).is_ok() {
            return Ok(None);
        }
        let non_optional_value = foreign.downcast_or_throw::<T::ArgType, _>(cx)?;
        T::borrow(cx, non_optional_value).map(Some)
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> Self {
        stored.as_mut().map(T::load_from)
    }
}

impl<'a> ArgTypeInfo<'a, 'a> for &'a [u8] {
    type ArgType = JsBuffer;
    // FIXME: Avoid copying this data.
    type StoredType = Vec<u8>;
    fn borrow(
        cx: &mut FunctionContext,
        foreign: Handle<'a, Self::ArgType>,
    ) -> NeonResult<Self::StoredType> {
        Ok(cx.borrow(&foreign, |buf| buf.as_slice().to_vec()))
    }
    fn load_from(stored: &'a mut Self::StoredType) -> Self {
        stored
    }
}

impl<'a> ResultTypeInfo<'a> for bool {
    type ResultType = JsBoolean;
    fn convert_into(self, cx: &mut impl Context<'a>) -> NeonResult<Handle<'a, Self::ResultType>> {
        Ok(cx.boolean(self))
    }
}

impl<'a> ResultTypeInfo<'a> for u64 {
    type ResultType = JsNumber;
    fn convert_into(self, cx: &mut impl Context<'a>) -> NeonResult<Handle<'a, Self::ResultType>> {
        let result = self as f64;
        if result > MAX_SAFE_JS_INTEGER {
            cx.throw_range_error(format!(
                "precision loss during conversion of {} to f64",
                self
            ))?;
        }
        Ok(cx.number(self as f64))
    }
}

impl<'a> ResultTypeInfo<'a> for String {
    type ResultType = JsString;
    fn convert_into(self, cx: &mut impl Context<'a>) -> NeonResult<Handle<'a, Self::ResultType>> {
        Ok(cx.string(self))
    }
}

impl<'a> ResultTypeInfo<'a> for &str {
    type ResultType = JsString;
    fn convert_into(self, cx: &mut impl Context<'a>) -> NeonResult<Handle<'a, Self::ResultType>> {
        Ok(cx.string(self))
    }
}

impl<'a, T: ResultTypeInfo<'a>> ResultTypeInfo<'a> for Option<T> {
    type ResultType = JsValue;
    fn convert_into(self, cx: &mut impl Context<'a>) -> NeonResult<Handle<'a, Self::ResultType>> {
        match self {
            Some(value) => Ok(value.convert_into(cx)?.upcast()),
            None => Ok(cx.null().upcast()),
        }
    }
}

impl<'a> ResultTypeInfo<'a> for Vec<u8> {
    type ResultType = JsBuffer;
    fn convert_into(self, cx: &mut impl Context<'a>) -> NeonResult<Handle<'a, Self::ResultType>> {
        let bytes_len = match u32::try_from(self.len()) {
            Ok(l) => l,
            Err(_) => return cx.throw_error("Cannot return very large object to JS environment"),
        };

        let mut buffer = cx.buffer(bytes_len)?;
        cx.borrow_mut(&mut buffer, |raw_buffer| {
            raw_buffer.as_mut_slice().copy_from_slice(&self);
        });
        Ok(buffer)
    }
}

impl<'a, T: ResultTypeInfo<'a>> ResultTypeInfo<'a>
    for Result<T, libsignal_protocol::SignalProtocolError>
{
    type ResultType = T::ResultType;
    fn convert_into(self, cx: &mut impl Context<'a>) -> NeonResult<Handle<'a, Self::ResultType>> {
        match self {
            Ok(value) => value.convert_into(cx),
            // FIXME: Use a dedicated Error type?
            Err(err) => cx.throw_error(err.to_string()),
        }
    }
}

impl<'a, T: ResultTypeInfo<'a>> ResultTypeInfo<'a> for Result<T, aes_gcm_siv::Error> {
    type ResultType = T::ResultType;
    fn convert_into(self, cx: &mut impl Context<'a>) -> NeonResult<Handle<'a, Self::ResultType>> {
        match self {
            Ok(value) => value.convert_into(cx),
            // FIXME: Use a dedicated Error type?
            Err(err) => cx.throw_error(err.to_string()),
        }
    }
}

impl<'a, T: ResultTypeInfo<'a>> ResultTypeInfo<'a> for NeonResult<T> {
    type ResultType = T::ResultType;
    fn convert_into(self, cx: &mut impl Context<'a>) -> NeonResult<Handle<'a, Self::ResultType>> {
        self?.convert_into(cx)
    }
}

impl<'a> ResultTypeInfo<'a> for () {
    type ResultType = JsUndefined;
    fn convert_into(self, cx: &mut impl Context<'a>) -> NeonResult<Handle<'a, Self::ResultType>> {
        Ok(cx.undefined())
    }
}

impl<'a, T: Value> ResultTypeInfo<'a> for Handle<'a, T> {
    type ResultType = T;
    fn convert_into(self, _cx: &mut impl Context<'a>) -> NeonResult<Handle<'a, Self::ResultType>> {
        Ok(self)
    }
}

macro_rules! full_range_integer {
    ($typ:ty) => {
        impl SimpleArgTypeInfo for $typ {
            type ArgType = JsNumber;
            fn convert_from(
                cx: &mut FunctionContext,
                foreign: Handle<Self::ArgType>,
            ) -> NeonResult<Self> {
                let value = foreign.value(cx);
                if !can_convert_js_number_to_int(value, 0.0..=<$typ>::MAX.into()) {
                    return cx.throw_range_error(format!(
                        "cannot convert {} to {}",
                        value,
                        stringify!($typ),
                    ));
                }
                Ok(value as $typ)
            }
        }
        impl<'a> ResultTypeInfo<'a> for $typ {
            type ResultType = JsNumber;
            fn convert_into(
                self,
                cx: &mut impl Context<'a>,
            ) -> NeonResult<Handle<'a, Self::ResultType>> {
                Ok(cx.number(self as f64))
            }
        }
    };
}

full_range_integer!(u8);
full_range_integer!(u32);
full_range_integer!(i32);

pub(crate) unsafe fn extend_lifetime<'a, 'b: 'a, T>(some_ref: &'a T) -> &'b T {
    std::mem::transmute::<&'a T, &'b T>(some_ref)
}

macro_rules! node_bridge_handle {
    ( $typ:ty as false ) => {};
    ( $typ:ty as $node_name:ident ) => {
        impl<'a> node::ArgTypeInfo<'a, 'a> for &'a $typ {
            type ArgType = node::DefaultJsBox<$typ>;
            type StoredType = node::Handle<'a, Self::ArgType>;
            fn borrow(
                _cx: &mut node::FunctionContext,
                foreign: node::Handle<'a, Self::ArgType>,
            ) -> node::NeonResult<Self::StoredType> {
                Ok(foreign)
            }
            fn load_from(
                foreign: &'a mut node::Handle<'a, Self::ArgType>,
            ) -> Self {
                &*foreign
            }
        }

        paste! {
            #[doc = "ts: interface " $typ " { readonly __type: unique symbol; }"]
            impl<'a> node::ResultTypeInfo<'a> for $typ {
                type ResultType = node::JsValue;
                fn convert_into(
                    self,
                    cx: &mut impl node::Context<'a>,
                ) -> node::NeonResult<node::Handle<'a, Self::ResultType>> {
                    node::return_boxed_object(cx, Ok(self))
                }
            }
        }
    };
    ( $typ:ty as $node_name:ident, mut = true ) => {
        impl<'storage, 'context: 'storage> node::ArgTypeInfo<'storage, 'context>
            for &'storage $typ
        {
            type ArgType = node::DefaultJsBox<std::cell::RefCell<$typ>>;
            type StoredType = (
                node::Handle<'context, Self::ArgType>,
                std::cell::Ref<'context, $typ>,
            );
            fn borrow(
                _cx: &mut node::FunctionContext,
                foreign: node::Handle<'context, Self::ArgType>,
            ) -> node::NeonResult<Self::StoredType> {
                let cell: &std::cell::RefCell<_> = &***foreign;
                // FIXME: Workaround for https://github.com/neon-bindings/neon/issues/678
                // The lifetime of the boxed RefCell is necessarily longer than the lifetime of any handles referring to it, i.e. longer than 'context.
                // However, Deref'ing a Handle can only give us a Ref whose lifetime matches a *particular* handle.
                // Therefore, we unsafely (in the compiler sense) extend the lifetime to be the lifetime of the context, as given by the Handle.
                // (We also know the RefCell can't move because we can't know how many JS references there are referring to the JsBox.)
                let cell_with_extended_lifetime: &'context std::cell::RefCell<_> = unsafe {
                    node::extend_lifetime(cell)
                };
                Ok((foreign, cell_with_extended_lifetime.borrow()))
            }
            fn load_from(
                stored: &'storage mut Self::StoredType,
            ) -> Self {
                &*stored.1
            }
        }

        impl<'storage, 'context: 'storage> node::ArgTypeInfo<'storage, 'context>
            for &'storage mut $typ
        {
            type ArgType = node::DefaultJsBox<std::cell::RefCell<$typ>>;
            type StoredType = (
                node::Handle<'context, Self::ArgType>,
                std::cell::RefMut<'context, $typ>,
            );
            fn borrow(
                _cx: &mut node::FunctionContext,
                foreign: node::Handle<'context, Self::ArgType>,
            ) -> node::NeonResult<Self::StoredType> {
                let cell: &std::cell::RefCell<_> = &***foreign;
                // See above.
                let cell_with_extended_lifetime: &'context std::cell::RefCell<_> = unsafe {
                    node::extend_lifetime(cell)
                };
                Ok((foreign, cell_with_extended_lifetime.borrow_mut()))
            }
            fn load_from(
                stored: &'storage mut Self::StoredType,
            ) -> Self {
                &mut *stored.1
            }
        }

        paste! {
            #[doc = "ts: interface " $typ " { readonly __type: unique symbol; }"]
            impl<'a> node::ResultTypeInfo<'a> for $typ {
                type ResultType = node::JsValue;
                fn convert_into(
                    self,
                    cx: &mut impl node::Context<'a>,
                ) -> node::NeonResult<node::Handle<'a, Self::ResultType>> {
                    node::return_boxed_object(cx, Ok(std::cell::RefCell::new(self)))
                }
            }
        }
    };
    ( $typ:ty $(, mut = $_:tt)?) => {
        paste! {
            node_bridge_handle!($typ as $typ $(, mut = $_)?);
        }
    };
}

impl<'a> crate::Env for &'_ mut FunctionContext<'a> {
    type Buffer = JsResult<'a, JsBuffer>;
    fn buffer<'b, T: Into<Cow<'b, [u8]>>>(self, input: T) -> Self::Buffer {
        let input = input.into();
        let len: u32 = input
            .len()
            .try_into()
            .or_else(|_| self.throw_error("buffer too large to return to JavaScript"))?;
        let mut result = Context::buffer(self, len)?;
        self.borrow_mut(&mut result, |buf| {
            buf.as_mut_slice().copy_from_slice(input.as_ref())
        });
        Ok(result)
    }
}
