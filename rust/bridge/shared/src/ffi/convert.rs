//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libc::{c_char, c_uchar, c_void};
use libsignal_protocol::*;
use paste::paste;
use std::borrow::Cow;
use std::ffi::CStr;

use super::*;

pub(crate) trait ArgTypeInfo<'a>: Sized {
    type ArgType;
    type StoredType;
    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType>;
    fn load_from(stored: &'a mut Self::StoredType) -> SignalFfiResult<Self>;
}

pub(crate) trait SimpleArgTypeInfo: Sized {
    type ArgType: Copy;
    fn convert_from(foreign: Self::ArgType) -> SignalFfiResult<Self>;
}

impl<'a, T> ArgTypeInfo<'a> for T
where
    T: SimpleArgTypeInfo,
{
    type ArgType = <Self as SimpleArgTypeInfo>::ArgType;
    type StoredType = Self::ArgType;
    fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
        Ok(foreign)
    }
    fn load_from(stored: &'a mut Self::StoredType) -> SignalFfiResult<Self> {
        Self::convert_from(*stored)
    }
}

pub(crate) trait SizedArgTypeInfo: Sized {
    type ArgType;
    fn convert_from(foreign: Self::ArgType, size: usize) -> SignalFfiResult<Self>;
}

pub(crate) trait ResultTypeInfo: Sized {
    type ResultType;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType>;
    fn write_to(ptr: *mut Self::ResultType, value: Self) -> SignalFfiResult<()> {
        if ptr.is_null() {
            return Err(SignalFfiError::NullPointer);
        }
        unsafe { *ptr = value.convert_into()? };
        Ok(())
    }
}

impl SizedArgTypeInfo for &[u8] {
    type ArgType = *const c_uchar;
    fn convert_from(input: Self::ArgType, input_len: usize) -> SignalFfiResult<Self> {
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

impl SizedArgTypeInfo for &mut [u8] {
    type ArgType = *mut c_uchar;
    fn convert_from(input: Self::ArgType, input_len: usize) -> SignalFfiResult<Self> {
        if input.is_null() {
            if input_len != 0 {
                return Err(SignalFfiError::NullPointer);
            }
            // We can't just fall through because slice::from_raw_parts_mut still expects a non-null pointer. Reference a dummy buffer instead.
            return Ok(&mut []);
        }

        unsafe { Ok(std::slice::from_raw_parts_mut(input, input_len)) }
    }
}

impl SimpleArgTypeInfo for Option<u32> {
    type ArgType = u32;
    fn convert_from(foreign: u32) -> SignalFfiResult<Self> {
        if foreign == u32::MAX {
            Ok(None)
        } else {
            Ok(Some(foreign))
        }
    }
}

impl SimpleArgTypeInfo for String {
    type ArgType = *const c_char;
    #[allow(clippy::not_unsafe_ptr_arg_deref)]
    fn convert_from(foreign: *const c_char) -> SignalFfiResult<Self> {
        if foreign.is_null() {
            return Err(SignalFfiError::NullPointer);
        }

        match unsafe { CStr::from_ptr(foreign).to_str() } {
            Ok(s) => Ok(s.to_owned()),
            Err(_) => Err(SignalFfiError::InvalidUtf8String),
        }
    }
}

impl SimpleArgTypeInfo for Option<String> {
    type ArgType = *const c_char;
    fn convert_from(foreign: *const c_char) -> SignalFfiResult<Self> {
        if foreign.is_null() {
            Ok(None)
        } else {
            String::convert_from(foreign).map(Some)
        }
    }
}

impl SimpleArgTypeInfo for Context {
    type ArgType = *mut c_void;
    fn convert_from(foreign: *mut c_void) -> SignalFfiResult<Self> {
        Ok(Some(foreign))
    }
}

macro_rules! store {
    ($name:ident) => {
        paste! {
            impl<'a> ArgTypeInfo<'a> for &'a mut dyn libsignal_protocol::$name {
                type ArgType = *const [<Ffi $name Struct>];
                type StoredType = &'a [<Ffi $name Struct>];
                fn borrow(foreign: Self::ArgType) -> SignalFfiResult<Self::StoredType> {
                    match unsafe { foreign.as_ref() } {
                        None => Err(SignalFfiError::NullPointer),
                        Some(store) => Ok(store),
                    }
                }
                fn load_from(stored: &'a mut Self::StoredType) -> SignalFfiResult<Self> {
                    Ok(stored)
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

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, SignalProtocolError> {
    type ResultType = T::ResultType;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        T::convert_into(self?)
    }
}

impl<T: ResultTypeInfo> ResultTypeInfo for Result<T, aes_gcm_siv::Error> {
    type ResultType = T::ResultType;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        T::convert_into(self?)
    }
}

impl ResultTypeInfo for String {
    type ResultType = *const libc::c_char;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        let cstr = CString::new(self).expect("No NULL characters in string being returned to C");
        Ok(cstr.into_raw())
    }
}

impl ResultTypeInfo for Option<String> {
    type ResultType = *const libc::c_char;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        match self {
            Some(s) => s.convert_into(),
            None => Ok(std::ptr::null()),
        }
    }
}

impl ResultTypeInfo for &str {
    type ResultType = *const libc::c_char;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        let cstr = CString::new(self).expect("No NULL characters in string being returned to C");
        Ok(cstr.into_raw())
    }
}

impl ResultTypeInfo for Option<&str> {
    type ResultType = *const libc::c_char;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        match self {
            Some(s) => s.convert_into(),
            None => Ok(std::ptr::null()),
        }
    }
}
impl ResultTypeInfo for Option<u32> {
    type ResultType = u32;
    fn convert_into(self) -> SignalFfiResult<Self::ResultType> {
        Ok(self.unwrap_or(u32::MAX))
    }
}

pub(crate) struct Env;

impl crate::support::Env for Env {
    type Buffer = Box<[u8]>;
    fn buffer<'a, T: Into<Cow<'a, [u8]>>>(self, input: T) -> Self::Buffer {
        input.into().into()
    }
}

macro_rules! ffi_bridge_handle {
    ( $typ:ty as false ) => {};
    ( $typ:ty as $ffi_name:ident, clone = false ) => {
        impl ffi::SimpleArgTypeInfo for &$typ {
            type ArgType = *const $typ;
            #[allow(clippy::not_unsafe_ptr_arg_deref)]
            fn convert_from(foreign: *const $typ) -> ffi::SignalFfiResult<Self> {
                unsafe { ffi::native_handle_cast(foreign) }
            }
        }
        impl ffi::SimpleArgTypeInfo for Option<&$typ> {
            type ArgType = *const $typ;
            fn convert_from(foreign: *const $typ) -> ffi::SignalFfiResult<Self> {
                if foreign.is_null() {
                    Ok(None)
                } else {
                    <&$typ>::convert_from(foreign).map(Some)
                }
            }
        }
        impl ffi::SimpleArgTypeInfo for &mut $typ {
            type ArgType = *mut $typ;
            #[allow(clippy::not_unsafe_ptr_arg_deref)]
            fn convert_from(foreign: *mut $typ) -> ffi::SignalFfiResult<Self> {
                unsafe { ffi::native_handle_cast_mut(foreign) }
            }
        }
        impl ffi::ResultTypeInfo for $typ {
            type ResultType = *mut $typ;
            fn convert_into(self) -> ffi::SignalFfiResult<Self::ResultType> {
                Ok(Box::into_raw(Box::new(self)))
            }
        }
        impl ffi::ResultTypeInfo for Option<$typ> {
            type ResultType = *mut $typ;
            fn convert_into(self) -> ffi::SignalFfiResult<Self::ResultType> {
                match self {
                    Some(obj) => obj.convert_into(),
                    None => Ok(std::ptr::null_mut()),
                }
            }
        }
        ffi_bridge_destroy!($typ as $ffi_name);
    };
    ( $typ:ty as $ffi_name:ident ) => {
        ffi_bridge_handle!($typ as $ffi_name, clone = false);
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<signal_ $ffi_name _clone>](
                new_obj: *mut *mut $typ,
                obj: *const $typ,
            ) -> *mut ffi::SignalFfiError {
                ffi::run_ffi_safe(|| {
                    let obj = ffi::native_handle_cast::<$typ>(obj)?;
                    ffi::box_object::<$typ>(new_obj, Ok(obj.clone()))
                })
            }
        }
    };
    ( $typ:ty $(, clone = $_:tt)? ) => {
        paste! {
            ffi_bridge_handle!($typ as [<$typ:snake>] $(, clone = $_)? );
        }
    };
}

macro_rules! trivial {
    ($typ:ty) => {
        impl SimpleArgTypeInfo for $typ {
            type ArgType = Self;
            fn convert_from(foreign: Self) -> SignalFfiResult<Self> {
                Ok(foreign)
            }
        }
        impl ResultTypeInfo for $typ {
            type ResultType = Self;
            fn convert_into(self) -> SignalFfiResult<Self> {
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
    (&mut [u8]) => (*mut libc::c_uchar);
    (String) => (*const libc::c_char);
    (Option<String>) => (*const libc::c_char);
    (Option<&str>) => (*const libc::c_char);
    (Context) => (*mut libc::c_void);
    (&mut dyn $typ:ty) => (*const paste!(ffi::[<Ffi $typ Struct>]));
    (& $typ:ty) => (*const $typ);
    (&mut $typ:ty) => (*mut $typ);
    (Option<& $typ:ty>) => (*const $typ);
}

macro_rules! ffi_result_type {
    (Result<$typ:tt $(, $_:ty)?>) => (ffi_result_type!($typ));
    (Result<&$typ:tt $(, $_:ty)?>) => (ffi_result_type!(&$typ));
    (Result<Option<&$typ:tt> $(, $_:ty)?>) => (ffi_result_type!(&$typ));
    (Result<$typ:tt<$($args:tt),+> $(, $_:ty)?>) => (ffi_result_type!($typ<$($args)+>));
    (u8) => (u8);
    (i32) => (i32);
    (u32) => (u32);
    (Option<u32>) => (u32);
    (u64) => (u64);
    (bool) => (bool);
    (&str) => (*const libc::c_char);
    (String) => (*const libc::c_char);
    (Option<String>) => (*const libc::c_char);
    (Option<&str>) => (*const libc::c_char);
    (Option<$typ:ty>) => (*mut $typ);
    ( $typ:ty ) => (*mut $typ);
}
