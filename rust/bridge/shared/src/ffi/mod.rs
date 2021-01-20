//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libc::{c_char, c_uchar, size_t};
use libsignal_protocol_rust::*;
use std::ffi::CString;

#[macro_use]
mod convert;
pub(crate) use convert::*;

mod error;
pub use error::*;

pub use crate::support::expect_ready;

pub fn run_ffi_safe<F: FnOnce() -> Result<(), SignalFfiError> + std::panic::UnwindSafe>(
    f: F,
) -> *mut SignalFfiError {
    let result = match std::panic::catch_unwind(f) {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(e),
        Err(r) => Err(SignalFfiError::UnexpectedPanic(r)),
    };

    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => Box::into_raw(Box::new(e)),
    }
}

pub unsafe fn box_object<T>(
    p: *mut *mut T,
    obj: Result<T, SignalProtocolError>,
) -> Result<(), SignalFfiError> {
    if p.is_null() {
        return Err(SignalFfiError::NullPointer);
    }
    match obj {
        Ok(o) => {
            *p = Box::into_raw(Box::new(o));
            Ok(())
        }
        Err(e) => {
            *p = std::ptr::null_mut();
            Err(SignalFfiError::Signal(e))
        }
    }
}

pub unsafe fn native_handle_cast<T>(handle: *const T) -> Result<&'static T, SignalFfiError> {
    if handle.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    Ok(&*(handle))
}

pub unsafe fn write_bytearray_to<T: Into<Box<[u8]>>>(
    out: *mut *const c_uchar,
    out_len: *mut size_t,
    value: T,
) -> Result<(), SignalFfiError> {
    if out.is_null() || out_len.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    let value: Box<[u8]> = value.into();

    *out_len = value.len();
    let mem = Box::into_raw(value);
    *out = (*mem).as_ptr();

    Ok(())
}

pub unsafe fn write_cstr_to(
    out: *mut *const c_char,
    value: Result<impl Into<Vec<u8>>, SignalProtocolError>,
) -> Result<(), SignalFfiError> {
    write_optional_cstr_to(out, value.map(Some))
}

pub unsafe fn write_optional_cstr_to(
    out: *mut *const c_char,
    value: Result<Option<impl Into<Vec<u8>>>, SignalProtocolError>,
) -> Result<(), SignalFfiError> {
    if out.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    match value {
        Ok(Some(value)) => {
            let cstr =
                CString::new(value).expect("No NULL characters in string being returned to C");
            *out = cstr.into_raw();
            Ok(())
        }
        Ok(None) => {
            *out = std::ptr::null();
            Ok(())
        }
        Err(e) => Err(SignalFfiError::Signal(e)),
    }
}

macro_rules! ffi_bridge_destroy {
    ( $typ:ty as None ) => {};
    ( $typ:ty as $ffi_name:ident ) => {
        paste! {
            #[cfg(feature = "ffi")]
            #[no_mangle]
            pub unsafe extern "C" fn [<signal_ $ffi_name _destroy>](
                p: *mut $typ
            ) -> *mut ffi::SignalFfiError {
                ffi::run_ffi_safe(|| {
                    if !p.is_null() {
                        Box::from_raw(p);
                    }
                    Ok(())
                })
            }
        }
    };
    ( $typ:ty ) => {
        paste! {
            ffi_bridge_destroy!($typ as [<$typ:snake>]);
        }
    };
}

macro_rules! ffi_bridge_deserialize {
    ( $typ:ident::$fn:path as None ) => {};
    ( $typ:ident::$fn:path as $ffi_name:ident ) => {
        paste! {
            #[cfg(feature = "ffi")]
            #[no_mangle]
            pub unsafe extern "C" fn [<signal_ $ffi_name _deserialize>](
                p: *mut *mut $typ,
                data: *const libc::c_uchar,
                data_len: libc::size_t,
            ) -> *mut ffi::SignalFfiError {
                ffi::run_ffi_safe(|| {
                    if data.is_null() {
                        return Err(ffi::SignalFfiError::NullPointer);
                    }
                    let data = std::slice::from_raw_parts(data, data_len);
                    ffi::box_object(p, $typ::$fn(data))
                })
            }
        }
    };
    ( $typ:ident::$fn:path ) => {
        paste! {
            ffi_bridge_deserialize!($typ::$fn as [<$typ:snake>]);
        }
    };
}

macro_rules! ffi_bridge_get_bytearray {
    ( $name:ident($typ:ty) as None => $body:expr ) => {};
    ( $name:ident($typ:ty) as $ffi_name:ident => $body:expr ) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<signal_ $ffi_name>](
                obj: *const $typ,
                out: *mut *const libc::c_uchar,
                out_len: *mut libc::size_t,
            ) -> *mut ffi::SignalFfiError {
                expr_as_fn!(inner_get<'a>(
                    obj: &'a $typ
                ) -> Result<impl Into<Box<[u8]>> + 'a, SignalProtocolError> => $body);
                ffi::run_ffi_safe(|| {
                    let obj = ffi::native_handle_cast::<$typ>(obj)?;
                    ffi::write_bytearray_to(out, out_len, inner_get(obj)?)
                })
            }
        }
    };
    ( $name:ident($typ:ty) => $body:expr ) => {
        paste! {
            ffi_bridge_get_bytearray!($name($typ) as [<$typ:snake _ $name>] => $body);
        }
    };
}

// Currently unneeded.
macro_rules! ffi_bridge_get_optional_bytearray {
    ( $name:ident($typ:ty) as None => $body:expr ) => {};
}

macro_rules! ffi_bridge_get_string {
    ( $name:ident($typ:ty) as None => $body:expr ) => {};
    ( $name:ident($typ:ty) as $ffi_name:ident => $body:expr ) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<signal_ $ffi_name>](
                obj: *const $typ,
                out: *mut *const libc::c_char,
            ) -> *mut ffi::SignalFfiError {
                expr_as_fn!(inner_get<'a>(
                    obj: &'a $typ
                ) -> Result<impl Into<Vec<u8>> + 'a, SignalProtocolError> => $body);
                ffi::run_ffi_safe(|| {
                    let obj = ffi::native_handle_cast::<$typ>(obj)?;
                    ffi::write_cstr_to(out, inner_get(obj))
                })
            }
        }
    };
    ( $name:ident($typ:ty) => $body:expr ) => {
        paste! {
            ffi_bridge_get_string!($name($typ) as [<$typ:snake _ $name>] => $body);
        }
    };
}

macro_rules! ffi_bridge_get_optional_string {
    ( $name:ident($typ:ty) as None => $body:expr ) => {};
    ( $name:ident($typ:ty) as $ffi_name:ident => $body:expr ) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<signal_ $ffi_name>](
                obj: *const $typ,
                out: *mut *const libc::c_char,
            ) -> *mut ffi::SignalFfiError {
                expr_as_fn!(inner_get<'a>(
                    obj: &'a $typ
                ) -> Result<Option<impl Into<Vec<u8>> + 'a>, SignalProtocolError> => $body);
                ffi::run_ffi_safe(|| {
                    let obj = ffi::native_handle_cast::<$typ>(obj)?;
                    ffi::write_optional_cstr_to(out, inner_get(obj))
                })
            }
        }
    };
    ( $name:ident($typ:ty) => $body:expr ) => {
        paste! {
            ffi_bridge_get_optional_string!($name($typ) as [<$typ:snake _ $name>] => $body);
        }
    };
}
