//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libc::{c_char, c_uchar};
use libsignal_protocol_rust::*;
use std::ffi::CStr;

use crate::ffi::*;

pub(crate) trait ArgTypeInfo: Sized {
    type ArgType;
    fn convert_from(foreign: Self::ArgType) -> Result<Self, SignalFfiError>;
}

pub(crate) trait SizedArgTypeInfo: Sized {
    type ArgType;
    fn convert_from(foreign: Self::ArgType, size: usize) -> Result<Self, SignalFfiError>;
}

pub(crate) trait ResultTypeInfo: Sized {
    type ResultType;
    fn convert_into(self) -> Result<Self::ResultType, SignalFfiError>;
    fn write_to(ptr: *mut Self::ResultType, value: Self) -> Result<(), SignalFfiError> {
        if ptr.is_null() {
            return Err(SignalFfiError::NullPointer);
        }
        unsafe { *ptr = value.convert_into()? };
        Ok(())
    }
}

impl SizedArgTypeInfo for &[u8] {
    type ArgType = *const c_uchar;
    fn convert_from(input: Self::ArgType, input_len: usize) -> Result<Self, SignalFfiError> {
        if input.is_null() {
            if input_len != 0 {
                return Err(SignalFfiError::NullPointer);
            }
            // We can't just fall through because slice::from_raw_parts still expects a non-null pointer. Reference a dummy buffer instead.
            return Ok(&[]);
        }

        unsafe { Ok(std::slice::from_raw_parts(input, input_len)) }
    }
}

impl ArgTypeInfo for String {
    type ArgType = *const c_char;
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(foreign: *const c_char) -> Result<Self, SignalFfiError> {
        if foreign.is_null() {
            return Err(SignalFfiError::NullPointer);
        }

        match unsafe { CStr::from_ptr(foreign).to_str() } {
            Ok(s) => Ok(s.to_owned()),
            Err(_) => Err(SignalFfiError::InvalidUtf8String),
        }
    }
}

impl<T> ArgTypeInfo for &'static T {
    type ArgType = *const T;
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(foreign: *const T) -> Result<Self, SignalFfiError> {
        unsafe { native_handle_cast(foreign) }
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, SignalProtocolError> {
    type ResultType = T::ResultType;
    fn convert_into(self) -> Result<Self::ResultType, SignalFfiError> {
        T::convert_into(self?)
    }
}

impl ResultTypeInfo for String {
    type ResultType = *const libc::c_char;
    fn convert_into(self) -> Result<Self::ResultType, SignalFfiError> {
        let cstr =
            CString::new(self).expect("No NULL characters in string being returned to C");
        Ok(cstr.into_raw())
    }
}

impl ResultTypeInfo for ProtocolAddress {
    type ResultType = *mut ProtocolAddress;
    fn convert_into(self) -> Result<Self::ResultType, SignalFfiError> {
        Ok(Box::into_raw(Box::new(self)))
    }
}

macro_rules! trivial {
    ($typ:ty) => {
        impl ArgTypeInfo for $typ {
            type ArgType = Self;
            fn convert_from(foreign: Self) -> Result<Self, SignalFfiError> { Ok(foreign) }
        }
        impl ResultTypeInfo for $typ {
            type ResultType = Self;
            fn convert_into(self) -> Result<Self, SignalFfiError> { Ok(self) }
        }
    }
}

trivial!(i32);
trivial!(u32);
trivial!(usize);
trivial!(bool);

macro_rules! ffi_arg_type {
    (u32) => (u32);
    (usize) => (libc::size_t);
    (&[u8]) => (*const libc::c_uchar);
    (String) => (*const libc::c_char);
    (& $typ:ty) => (*const $typ);
}

macro_rules! ffi_result_type {
    (Result<$typ:tt, $_:tt>) => (ffi_result_type!($typ));
    (i32) => (i32);
    (bool) => (bool);
    (String) => (*const libc::c_char);
    ( $typ:ty ) => (*mut $typ);
}
