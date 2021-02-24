//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use neon::prelude::*;
use paste::paste;
use std::borrow::Cow;
use std::collections::hash_map::DefaultHasher;
use std::convert::{TryFrom, TryInto};
use std::hash::Hasher;
use std::ops::{Deref, RangeInclusive};
use std::slice;

use super::*;

pub trait ArgTypeInfo<'storage, 'context: 'storage>: Sized {
    type ArgType: neon::types::Value;
    type StoredType: 'storage;
    fn borrow(
        cx: &mut FunctionContext<'context>,
        foreign: Handle<'context, Self::ArgType>,
    ) -> NeonResult<Self::StoredType>;
    fn load_from(stored: &'storage mut Self::StoredType) -> Self;
}

pub(crate) trait AsyncArgTypeInfo<'storage>: Sized {
    type ArgType: neon::types::Value;
    type StoredType: 'static + Finalize;
    fn save_async_arg(
        cx: &mut FunctionContext,
        foreign: Handle<Self::ArgType>,
    ) -> NeonResult<Self::StoredType>;
    fn load_async_arg(stored: &'storage mut Self::StoredType) -> Self;
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
        cx: &mut FunctionContext<'a>,
        foreign: Handle<'a, Self::ArgType>,
    ) -> NeonResult<Self::StoredType> {
        Ok(Some(Self::convert_from(cx, foreign)?))
    }
    fn load_from(stored: &'a mut Self::StoredType) -> Self {
        stored.take().expect("should only be loaded once")
    }
}

impl<'a, T> AsyncArgTypeInfo<'a> for T
where
    T: SimpleArgTypeInfo,
{
    type ArgType = T::ArgType;
    type StoredType = super::DefaultFinalize<Option<Self>>;
    fn save_async_arg(
        cx: &mut FunctionContext,
        foreign: Handle<Self::ArgType>,
    ) -> NeonResult<Self::StoredType> {
        Ok(super::DefaultFinalize(Some(Self::convert_from(
            cx, foreign,
        )?)))
    }
    fn load_async_arg(stored: &'a mut Self::StoredType) -> Self {
        stored.0.take().expect("should only be loaded once")
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
        cx: &mut FunctionContext<'context>,
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

pub(crate) struct FinalizableOption<T: Finalize>(Option<T>);

impl<T: Finalize> Finalize for FinalizableOption<T> {
    fn finalize<'a, C: Context<'a>>(self, cx: &mut C) {
        if let Some(value) = self.0 {
            value.finalize(cx)
        }
    }
}

impl<'storage, T> AsyncArgTypeInfo<'storage> for Option<T>
where
    T: AsyncArgTypeInfo<'storage>,
{
    type ArgType = JsValue;
    type StoredType = FinalizableOption<T::StoredType>;
    fn save_async_arg(
        cx: &mut FunctionContext,
        foreign: Handle<Self::ArgType>,
    ) -> NeonResult<Self::StoredType> {
        if foreign.downcast::<JsNull, _>(cx).is_ok() {
            return Ok(FinalizableOption(None));
        }
        let non_optional_value = foreign.downcast_or_throw::<T::ArgType, _>(cx)?;
        Ok(FinalizableOption(Some(T::save_async_arg(
            cx,
            non_optional_value,
        )?)))
    }
    fn load_async_arg(stored: &'storage mut Self::StoredType) -> Self {
        stored.0.as_mut().map(T::load_async_arg)
    }
}

fn calculate_checksum_for_immutable_buffer(buffer: &[u8]) -> u64 {
    let mut hasher = DefaultHasher::new();
    const LIMIT: usize = 1024;
    if log::log_enabled!(log::Level::Debug) || buffer.len() < LIMIT {
        hasher.write(buffer);
    } else {
        hasher.write(&buffer[..LIMIT]);
    }
    hasher.finish()
}

pub struct AssumedImmutableBuffer<'a> {
    buffer: &'a [u8],
    hash: u64,
}

impl<'a> AssumedImmutableBuffer<'a> {
    fn new<'b>(cx: &mut impl Context<'b>, handle: Handle<'a, JsBuffer>) -> Self {
        // A JsBuffer owns its storage*, so it's safe to assume the buffer won't get deallocated.
        // What's unsafe is assuming that no one else will modify the buffer
        // while we have a reference to it, which is why we checksum it.
        // (We can't stop the Rust compiler from potentially optimizing out that checksum, though.)
        //
        // * https://nodejs.org/api/n-api.html#n_api_napi_get_buffer_info
        let buffer = cx.borrow(&handle, |buf| {
            if buf.len() == 0 {
                &[]
            } else {
                unsafe { extend_lifetime::<'_, 'a, [u8]>(buf.as_slice()) }
            }
        });
        let hash = calculate_checksum_for_immutable_buffer(buffer);
        Self { buffer, hash }
    }
}

impl Drop for AssumedImmutableBuffer<'_> {
    fn drop(&mut self) {
        if self.hash != calculate_checksum_for_immutable_buffer(self.buffer) {
            log::error!("buffer modified while in use");
        }
    }
}

impl<'storage, 'context: 'storage> ArgTypeInfo<'storage, 'context> for &'storage [u8] {
    type ArgType = JsBuffer;
    type StoredType = AssumedImmutableBuffer<'context>;
    fn borrow(
        cx: &mut FunctionContext,
        foreign: Handle<'context, Self::ArgType>,
    ) -> NeonResult<Self::StoredType> {
        Ok(AssumedImmutableBuffer::new(cx, foreign))
    }
    fn load_from(stored: &'storage mut Self::StoredType) -> Self {
        stored.buffer
    }
}

pub(crate) struct PersistentAssumedImmutableBuffer {
    owner: Root<JsBuffer>,
    buffer_start: *const u8,
    buffer_len: usize,
    hash: u64,
}

impl PersistentAssumedImmutableBuffer {
    fn new<'a>(cx: &mut impl Context<'a>, buffer: Handle<JsBuffer>) -> Self {
        let owner = buffer.root(cx);
        let (buffer_start, buffer_len, hash) = cx.borrow(&buffer, |buf| {
            (
                if buf.len() == 0 {
                    std::ptr::null()
                } else {
                    buf.as_slice().as_ptr()
                },
                buf.len(),
                calculate_checksum_for_immutable_buffer(buf.as_slice()),
            )
        });
        Self {
            owner,
            buffer_start,
            buffer_len,
            hash,
        }
    }
}

impl Deref for PersistentAssumedImmutableBuffer {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // A JsBuffer owns its storage*, so it's safe to assume the buffer hasn't been deallocated.
        // What's unsafe is assuming that no one else will modify the buffer
        // while we have a reference to it, which is why we checksum it.
        // (We can't stop the Rust compiler from potentially optimizing out that checksum, though.)
        //
        // * https://nodejs.org/api/n-api.html#n_api_napi_get_buffer_info
        if self.buffer_start.is_null() {
            &[]
        } else {
            unsafe { slice::from_raw_parts(self.buffer_start, self.buffer_len) }
        }
    }
}

// PersistentAssumedImmutableBuffer is not automatically Send because it contains a pointer.
// We're already assuming (and checking) that the contents of the buffer won't be modified
// while in use, and we know it won't be deallocated (see above).
unsafe impl Send for PersistentAssumedImmutableBuffer {}

impl Finalize for PersistentAssumedImmutableBuffer {
    fn finalize<'a, C: Context<'a>>(self, cx: &mut C) {
        if self.hash != calculate_checksum_for_immutable_buffer(&*self) {
            log::error!("buffer modified while in use");
        }
        self.owner.finalize(cx)
    }
}

impl<'a> AsyncArgTypeInfo<'a> for &'a [u8] {
    type ArgType = JsBuffer;
    type StoredType = PersistentAssumedImmutableBuffer;
    fn save_async_arg(
        cx: &mut FunctionContext,
        foreign: Handle<Self::ArgType>,
    ) -> NeonResult<Self::StoredType> {
        Ok(PersistentAssumedImmutableBuffer::new(cx, foreign))
    }
    fn load_async_arg(stored: &'a mut Self::StoredType) -> Self {
        &*stored
    }
}

macro_rules! store {
    ($name:ident) => {
        paste! {
            impl<'a> AsyncArgTypeInfo<'a> for &'a mut dyn libsignal_protocol::$name {
                type ArgType = JsObject;
                type StoredType = [<Node $name>];
                fn save_async_arg(
                    cx: &mut FunctionContext,
                    foreign: Handle<Self::ArgType>,
                ) -> NeonResult<Self::StoredType> {
                    Ok(Self::StoredType::new(cx, foreign))
                }
                fn load_async_arg(stored: &'a mut Self::StoredType) -> Self {
                    stored
                }
            }
        }
    };
}

store!(IdentityKeyStore);
store!(PreKeyStore);
store!(SenderKeyStore);
store!(SessionStore);
store!(SignedPreKeyStore);

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
        self.deref().convert_into(cx)
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

pub(crate) unsafe fn extend_lifetime<'a, 'b: 'a, T: ?Sized>(some_ref: &'a T) -> &'b T {
    std::mem::transmute::<&'a T, &'b T>(some_ref)
}

pub(crate) const NATIVE_HANDLE_PROPERTY: &str = "_nativeHandle";

pub(crate) struct PersistentBoxedValue<T: Send + Sync + 'static> {
    owner: Root<JsObject>,
    value_ptr: *const T,
}

impl<T: Send + Sync + 'static> PersistentBoxedValue<T> {
    pub(crate) fn new<'a>(
        cx: &mut impl Context<'a>,
        wrapper: Handle<JsObject>,
    ) -> NeonResult<Self> {
        let value_box: Handle<super::DefaultJsBox<T>> = wrapper
            .get(cx, NATIVE_HANDLE_PROPERTY)?
            .downcast_or_throw(cx)?;
        let value_ptr = &***value_box as *const T;
        // We must create the root after all failable operations.
        let owner = wrapper.root(cx);
        Ok(Self { owner, value_ptr })
    }
}

impl<T: Send + Sync + 'static> Deref for PersistentBoxedValue<T> {
    type Target = T;
    fn deref(&self) -> &T {
        // We're unsafely assuming that `self.owner` still has a reference to the JsBox containing
        // the storage referenced by `self.value_ptr`.
        // N-API won't let us put a JsBox in a Root, so this indirection is necessary.
        unsafe { self.value_ptr.as_ref().expect("JsBox never contains NULL") }
    }
}

// PersistentBoxedValue is not automatically Send because it contains a pointer.
// We already know the contents of the value are only accessible to Rust, immutably,
// and we're promising it won't be deallocated (see above).
unsafe impl<T: Send + Sync + 'static> Send for PersistentBoxedValue<T> {}

impl<T: Send + Sync + 'static> Finalize for PersistentBoxedValue<T> {
    fn finalize<'a, C: Context<'a>>(self, cx: &mut C) {
        self.owner.finalize(cx)
    }
}

macro_rules! node_bridge_handle {
    ( $typ:ty as false ) => {};
    ( $typ:ty as $node_name:ident ) => {
        impl<'storage, 'context: 'storage> node::ArgTypeInfo<'storage, 'context>
        for &'storage $typ {
            type ArgType = node::JsObject;
            type StoredType = node::Handle<'context, node::DefaultJsBox<$typ>>;
            fn borrow(
                cx: &mut node::FunctionContext<'context>,
                foreign: node::Handle<'context, Self::ArgType>,
            ) -> node::NeonResult<Self::StoredType> {
                node::Object::get(*foreign, cx, node::NATIVE_HANDLE_PROPERTY)?.downcast_or_throw(cx)
            }
            fn load_from(
                foreign: &'storage mut Self::StoredType,
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

        impl<'storage> node::AsyncArgTypeInfo<'storage> for &'storage $typ {
            type ArgType = node::JsObject;
            type StoredType = node::PersistentBoxedValue<$typ>;
            fn save_async_arg(
                cx: &mut node::FunctionContext,
                foreign: node::Handle<Self::ArgType>,
            ) -> node::NeonResult<Self::StoredType> {
                node::PersistentBoxedValue::new(cx, foreign)
            }
            fn load_async_arg(
                stored: &'storage mut Self::StoredType,
            ) -> Self {
                &*stored
            }
        }
    };
    ( $typ:ty as $node_name:ident, mut = true ) => {
        impl<'storage, 'context: 'storage> node::ArgTypeInfo<'storage, 'context>
            for &'storage $typ
        {
            type ArgType = node::JsObject;
            type StoredType = (
                node::Handle<'context, node::DefaultJsBox<std::cell::RefCell<$typ>>>,
                std::cell::Ref<'context, $typ>,
            );
            fn borrow(
                cx: &mut node::FunctionContext<'context>,
                foreign: node::Handle<'context, Self::ArgType>,
            ) -> node::NeonResult<Self::StoredType> {
                let boxed_value: node::Handle<'context, node::DefaultJsBox<std::cell::RefCell<$typ>>> =
                    node::Object::get(*foreign, cx, node::NATIVE_HANDLE_PROPERTY)?.downcast_or_throw(cx)?;
                let cell: &std::cell::RefCell<_> = &***boxed_value;
                // FIXME: Workaround for https://github.com/neon-bindings/neon/issues/678
                // The lifetime of the boxed RefCell is necessarily longer than the lifetime of any handles referring to it, i.e. longer than 'context.
                // However, Deref'ing a Handle can only give us a Ref whose lifetime matches a *particular* handle.
                // Therefore, we unsafely (in the compiler sense) extend the lifetime to be the lifetime of the context, as given by the Handle.
                // (We also know the RefCell can't move because we can't know how many JS references there are referring to the JsBox.)
                let cell_with_extended_lifetime: &'context std::cell::RefCell<_> = unsafe {
                    node::extend_lifetime(cell)
                };
                Ok((boxed_value, cell_with_extended_lifetime.borrow()))
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

impl<'a> crate::support::Env for &'_ mut FunctionContext<'a> {
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

pub(crate) struct AsyncEnv;

impl crate::support::Env for AsyncEnv {
    // FIXME: Can we avoid this copy?
    type Buffer = Vec<u8>;
    fn buffer<'b, T: Into<Cow<'b, [u8]>>>(self, input: T) -> Self::Buffer {
        input.into().into_owned()
    }
}
