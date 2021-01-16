//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libc::{c_char, c_uchar};
use libsignal_protocol_rust::*;
use std::borrow::Cow;
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

impl ArgTypeInfo for Option<u32> {
    type ArgType = u32;
    fn convert_from(foreign: u32) -> Result<Self, SignalFfiError> {
        if foreign == u32::MAX {
            Ok(None)
        } else {
            Ok(Some(foreign))
        }
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

impl ArgTypeInfo for Option<String> {
    type ArgType = *const c_char;
    fn convert_from(foreign: *const c_char) -> Result<Self, SignalFfiError> {
        if foreign.is_null() {
            Ok(None)
        } else {
            String::convert_from(foreign).map(Some)
        }
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
        let cstr = CString::new(self).expect("No NULL characters in string being returned to C");
        Ok(cstr.into_raw())
    }
}

pub(crate) struct Env;

impl crate::Env for Env {
    type Buffer = Box<[u8]>;
    fn buffer<'a, T: Into<Cow<'a, [u8]>>>(&self, input: T) -> Self::Buffer {
        input.into().into()
    }
}

macro_rules! ffi_bridge_handle {
    ($typ:ty) => {
        impl ffi::ArgTypeInfo for &'static $typ {
            type ArgType = *const $typ;
            #[allow(clippy::not_unsafe_ptr_arg_deref)]
            fn convert_from(foreign: *const $typ) -> Result<Self, ffi::SignalFfiError> {
                unsafe { ffi::native_handle_cast(foreign) }
            }
        }
        impl ffi::ResultTypeInfo for $typ {
            type ResultType = *mut $typ;
            fn convert_into(self) -> Result<Self::ResultType, ffi::SignalFfiError> {
                Ok(Box::into_raw(Box::new(self)))
            }
        }
    };
}

macro_rules! trivial {
    ($typ:ty) => {
        impl ArgTypeInfo for $typ {
            type ArgType = Self;
            fn convert_from(foreign: Self) -> Result<Self, SignalFfiError> {
                Ok(foreign)
            }
        }
        impl ResultTypeInfo for $typ {
            type ResultType = Self;
            fn convert_into(self) -> Result<Self, SignalFfiError> {
                Ok(self)
            }
        }
    };
}

trivial!(i32);
trivial!(u8);
trivial!(u32);
trivial!(u64);
trivial!(usize);
trivial!(bool);

macro_rules! ffi_arg_type {
    (u8) => (u8);
    (u32) => (u32);
    (u64) => (u64);
    (Option<u32>) => (u32);
    (usize) => (libc::size_t);
    (&[u8]) => (*const libc::c_uchar);
    (String) => (*const libc::c_char);
    (Option<String>) => (*const libc::c_char);
    (& $typ:ty) => (*const $typ);
}

macro_rules! ffi_result_type {
    (Result<$typ:tt, $_:tt>) => (ffi_result_type!($typ));
    (i32) => (i32);
    (bool) => (bool);
    (String) => (*const libc::c_char);
    ( $typ:ty ) => (*mut $typ);
}
