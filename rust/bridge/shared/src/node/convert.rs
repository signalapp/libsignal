//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use neon::prelude::*;
use std::borrow::Cow;
use std::convert::TryInto;
use std::ops::{Deref, RangeInclusive};

pub(crate) trait ArgTypeInfo<'a>: Sized {
    type ArgType: neon::types::Value;
    fn convert_from(
        cx: &mut FunctionContext<'a>,
        foreign: Handle<'a, Self::ArgType>,
    ) -> NeonResult<Self>;
}

pub(crate) trait RefArgTypeInfo<'a>: Deref {
    type ArgType: neon::types::Value;
    type StoredType: Deref<Target = Self::Target> + 'a;
    fn convert_from(
        cx: &mut FunctionContext<'a>,
        foreign: Handle<'a, Self::ArgType>,
    ) -> NeonResult<Self::StoredType>;
}

pub(crate) trait ResultTypeInfo<'a>: Sized {
    type ResultType: neon::types::Value;
    fn convert_into(self, cx: &mut FunctionContext<'a>)
        -> NeonResult<Handle<'a, Self::ResultType>>;
}

fn can_convert_js_number_to_int(value: f64, valid_range: RangeInclusive<f64>) -> bool {
    value.is_finite() && value.fract() == 0.0 && valid_range.contains(&value)
}

impl<'a> ArgTypeInfo<'a> for u32 {
    type ArgType = JsNumber;
    fn convert_from(
        cx: &mut FunctionContext<'a>,
        foreign: Handle<'a, Self::ArgType>,
    ) -> NeonResult<Self> {
        let value = foreign.value(cx);
        if !can_convert_js_number_to_int(value, 0.0..=u32::MAX.into()) {
            return cx
                .throw_range_error(format!("integer overflow during conversion of {}", value));
        }
        Ok(value as u32)
    }
}

impl<'a> ArgTypeInfo<'a> for u8 {
    type ArgType = JsNumber;
    fn convert_from(
        cx: &mut FunctionContext<'a>,
        foreign: Handle<'a, Self::ArgType>,
    ) -> NeonResult<Self> {
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

impl<'a> ArgTypeInfo<'a> for u64 {
    type ArgType = JsNumber;
    fn convert_from(
        cx: &mut FunctionContext<'a>,
        foreign: Handle<'a, Self::ArgType>,
    ) -> NeonResult<Self> {
        let value = foreign.value(cx);
        if !can_convert_js_number_to_int(value, 0.0..=MAX_SAFE_JS_INTEGER) {
            return cx
                .throw_range_error(format!("integer overflow during conversion of {}", value));
        }
        Ok(value as u64)
    }
}

impl<'a> ArgTypeInfo<'a> for String {
    type ArgType = JsString;
    fn convert_from(
        cx: &mut FunctionContext<'a>,
        foreign: Handle<'a, Self::ArgType>,
    ) -> NeonResult<Self> {
        Ok(foreign.value(cx))
    }
}

impl<'a, T: ArgTypeInfo<'a>> ArgTypeInfo<'a> for Option<T> {
    type ArgType = JsValue;
    fn convert_from(
        cx: &mut FunctionContext<'a>,
        foreign: Handle<'a, Self::ArgType>,
    ) -> NeonResult<Self> {
        if foreign.downcast::<JsNull, _>(cx).is_ok() {
            return Ok(None);
        }
        let non_optional_value = foreign.downcast_or_throw::<T::ArgType, _>(cx)?;
        T::convert_from(cx, non_optional_value).map(Some)
    }
}

impl<'a> RefArgTypeInfo<'a> for &[u8] {
    type ArgType = JsBuffer;
    // FIXME: Avoid copying this data.
    type StoredType = Vec<u8>;
    fn convert_from(
        cx: &mut FunctionContext<'a>,
        foreign: Handle<'a, Self::ArgType>,
    ) -> NeonResult<Self::StoredType> {
        Ok(cx.borrow(&foreign, |buf| buf.as_slice().to_vec()))
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

pub(crate) struct RefBoxHandle<'a, T: Send + 'static> {
    pub(crate) data: Handle<'a, crate::node::DefaultJsBox<T>>,
}

impl<'a, T: Send + 'static> Deref for RefBoxHandle<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &***self.data
    }
}

macro_rules! node_bridge_handle {
    ($typ:ty) => {
        impl<'a> node::RefArgTypeInfo<'a> for &$typ {
            type ArgType = node::DefaultJsBox<$typ>;
            type StoredType = node::RefBoxHandle<'a, $typ>;
            fn convert_from(
                _cx: &mut node::FunctionContext<'a>,
                foreign: node::Handle<'a, Self::ArgType>,
            ) -> node::NeonResult<Self::StoredType> {
                Ok(node::RefBoxHandle { data: foreign })
            }
        }
        impl<'a> node::ResultTypeInfo<'a> for $typ {
            type ResultType = node::JsValue;
            fn convert_into(
                self,
                cx: &mut node::FunctionContext<'a>,
            ) -> node::NeonResult<node::Handle<'a, Self::ResultType>> {
                node::return_boxed_object(cx, Ok(self))
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
