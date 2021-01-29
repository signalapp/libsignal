//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use neon::prelude::*;
use std::borrow::Cow;
use std::convert::TryInto;
use std::ops::RangeInclusive;

pub(crate) trait ArgTypeInfo<'a>: Sized {
    type ArgType: neon::types::Value;
    type StoredType: 'a;
    fn borrow(
        cx: &mut FunctionContext,
        foreign: Handle<'a, Self::ArgType>,
    ) -> NeonResult<Self::StoredType>;
    fn load_from(cx: &mut FunctionContext, stored: &'a mut Self::StoredType) -> NeonResult<Self>;
}

pub trait SimpleArgTypeInfo: Sized {
    type ArgType: neon::types::Value;
    fn convert_from(cx: &mut FunctionContext, foreign: Handle<Self::ArgType>) -> NeonResult<Self>;
}

impl<'a, T> ArgTypeInfo<'a> for T
where
    T: SimpleArgTypeInfo,
{
    type ArgType = T::ArgType;
    type StoredType = Handle<'a, Self::ArgType>;
    fn borrow(
        _cx: &mut FunctionContext,
        foreign: Handle<'a, Self::ArgType>,
    ) -> NeonResult<Self::StoredType> {
        Ok(foreign)
    }
    fn load_from(cx: &mut FunctionContext, stored: &'a mut Self::StoredType) -> NeonResult<Self> {
        Self::convert_from(cx, *stored)
    }
}

pub(crate) trait ResultTypeInfo<'a>: Sized {
    type ResultType: neon::types::Value;
    fn convert_into(self, cx: &mut FunctionContext<'a>)
        -> NeonResult<Handle<'a, Self::ResultType>>;
}

fn can_convert_js_number_to_int(value: f64, valid_range: RangeInclusive<f64>) -> bool {
    value.is_finite() && value.fract() == 0.0 && valid_range.contains(&value)
}

impl SimpleArgTypeInfo for u32 {
    type ArgType = JsNumber;
    fn convert_from(cx: &mut FunctionContext, foreign: Handle<Self::ArgType>) -> NeonResult<Self> {
        let value = foreign.value(cx);
        if !can_convert_js_number_to_int(value, 0.0..=u32::MAX.into()) {
            return cx
                .throw_range_error(format!("integer overflow during conversion of {}", value));
        }
        Ok(value as u32)
    }
}

impl SimpleArgTypeInfo for u8 {
    type ArgType = JsNumber;
    fn convert_from(cx: &mut FunctionContext, foreign: Handle<Self::ArgType>) -> NeonResult<Self> {
        let value = foreign.value(cx);
        if !can_convert_js_number_to_int(value, 0.0..=u8::MAX.into()) {
            return cx
                .throw_range_error(format!("integer overflow during conversion of {}", value));
        }
        Ok(value as u8)
    }
}

// 2**53 - 1, the maximum "safe" integer representable in an f64.
// https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/MAX_SAFE_INTEGER
const MAX_SAFE_JS_INTEGER: f64 = 9007199254740991.0;

impl SimpleArgTypeInfo for u64 {
    type ArgType = JsNumber;
    fn convert_from(cx: &mut FunctionContext, foreign: Handle<Self::ArgType>) -> NeonResult<Self> {
        let value = foreign.value(cx);
        if !can_convert_js_number_to_int(value, 0.0..=MAX_SAFE_JS_INTEGER) {
            return cx
                .throw_range_error(format!("integer overflow during conversion of {}", value));
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

impl<'a, T: ArgTypeInfo<'a>> ArgTypeInfo<'a> for Option<T> {
    type ArgType = JsValue;
    type StoredType = Option<T::StoredType>;
    fn borrow(
        cx: &mut FunctionContext,
        foreign: Handle<'a, Self::ArgType>,
    ) -> NeonResult<Self::StoredType> {
        if foreign.downcast::<JsNull, _>(cx).is_ok() {
            return Ok(None);
        }
        let non_optional_value = foreign.downcast_or_throw::<T::ArgType, _>(cx)?;
        T::borrow(cx, non_optional_value).map(Some)
    }
    fn load_from(cx: &mut FunctionContext, stored: &'a mut Self::StoredType) -> NeonResult<Self> {
        match stored {
            None => Ok(None),
            Some(non_optional_stored) => T::load_from(cx, non_optional_stored).map(Some),
        }
    }
}

impl<'a> ArgTypeInfo<'a> for &'a [u8] {
    type ArgType = JsBuffer;
    // FIXME: Avoid copying this data.
    type StoredType = Vec<u8>;
    fn borrow(
        cx: &mut FunctionContext,
        foreign: Handle<'a, Self::ArgType>,
    ) -> NeonResult<Self::StoredType> {
        Ok(cx.borrow(&foreign, |buf| buf.as_slice().to_vec()))
    }
    fn load_from(_cx: &mut FunctionContext, stored: &'a mut Self::StoredType) -> NeonResult<Self> {
        Ok(stored)
    }
}

impl<'a> ResultTypeInfo<'a> for bool {
    type ResultType = JsBoolean;
    fn convert_into(
        self,
        cx: &mut FunctionContext<'a>,
    ) -> NeonResult<Handle<'a, Self::ResultType>> {
        Ok(cx.boolean(self))
    }
}

impl<'a> ResultTypeInfo<'a> for i32 {
    type ResultType = JsNumber;
    fn convert_into(
        self,
        cx: &mut FunctionContext<'a>,
    ) -> NeonResult<Handle<'a, Self::ResultType>> {
        Ok(cx.number(self as f64))
    }
}

impl<'a> ResultTypeInfo<'a> for String {
    type ResultType = JsString;
    fn convert_into(
        self,
        cx: &mut FunctionContext<'a>,
    ) -> NeonResult<Handle<'a, Self::ResultType>> {
        Ok(cx.string(self))
    }
}

impl<'a, T: ResultTypeInfo<'a>> ResultTypeInfo<'a>
    for Result<T, libsignal_protocol_rust::SignalProtocolError>
{
    type ResultType = T::ResultType;
    fn convert_into(
        self,
        cx: &mut FunctionContext<'a>,
    ) -> NeonResult<Handle<'a, Self::ResultType>> {
        match self {
            Ok(value) => value.convert_into(cx),
            // FIXME: Use a dedicated Error type?
            Err(err) => cx.throw_error(err.to_string()),
        }
    }
}

impl<'a, T: ResultTypeInfo<'a>> ResultTypeInfo<'a> for Result<T, aes_gcm_siv::Error> {
    type ResultType = T::ResultType;
    fn convert_into(
        self,
        cx: &mut FunctionContext<'a>,
    ) -> NeonResult<Handle<'a, Self::ResultType>> {
        match self {
            Ok(value) => value.convert_into(cx),
            // FIXME: Use a dedicated Error type?
            Err(err) => cx.throw_error(err.to_string()),
        }
    }
}

impl<'a, T: ResultTypeInfo<'a>> ResultTypeInfo<'a> for NeonResult<T> {
    type ResultType = T::ResultType;
    fn convert_into(
        self,
        cx: &mut FunctionContext<'a>,
    ) -> NeonResult<Handle<'a, Self::ResultType>> {
        self?.convert_into(cx)
    }
}

impl<'a, T: Value> ResultTypeInfo<'a> for Handle<'a, T> {
    type ResultType = T;
    fn convert_into(
        self,
        _cx: &mut FunctionContext<'a>,
    ) -> NeonResult<Handle<'a, Self::ResultType>> {
        Ok(self)
    }
}

macro_rules! node_bridge_handle {
    ($typ:ty) => {
        impl<'a> node::ArgTypeInfo<'a> for &'a $typ {
            type ArgType = node::DefaultJsBox<$typ>;
            type StoredType = node::Handle<'a, Self::ArgType>;
            fn borrow(
                _cx: &mut node::FunctionContext,
                foreign: node::Handle<'a, Self::ArgType>,
            ) -> node::NeonResult<Self::StoredType> {
                Ok(foreign)
            }
            fn load_from(
                _cx: &mut node::FunctionContext,
                foreign: &'a mut node::Handle<'a, Self::ArgType>,
            ) -> node::NeonResult<Self> {
                Ok(&*foreign)
            }
        }

        paste! {
            #[doc = "ts: interface " $typ " { readonly __type: unique symbol; }"]
            impl<'a> node::ResultTypeInfo<'a> for $typ {
                type ResultType = node::JsValue;
                fn convert_into(
                    self,
                    cx: &mut node::FunctionContext<'a>,
                ) -> node::NeonResult<node::Handle<'a, Self::ResultType>> {
                    node::return_boxed_object(cx, Ok(self))
                }
            }
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
