//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol_rust::*;

pub(crate) use libc::{c_uchar, size_t};
pub(crate) use paste::paste;
pub(crate) use std::convert::TryFrom;

mod error;
pub use error::*;

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

macro_rules! bridge_destroy {
    ( $typ:ty, ffi = $ffi_name:ident $(, jni = $jni_name:ident)? ) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<signal_ $ffi_name _destroy>](p: *mut $typ) -> *mut SignalFfiError {
                run_ffi_safe(|| {
                    if !p.is_null() {
                        Box::from_raw(p);
                    }
                    Ok(())
                })
            }
        }
    };
    ( $typ:ty $(, jni = $jni_name:ident)?) => {
        paste! {
            bridge_destroy!($typ, ffi = [<$typ:snake>]);
        }
    }
}

macro_rules! bridge_deserialize {
    ( $typ:ident::$fn:path, ffi = $ffi_name:ident $(, jni = $jni_name:ident)? ) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [<signal_ $ffi_name _deserialize>](
                p: *mut *mut $typ,
                data: *const c_uchar,
                data_len: size_t,
            ) -> *mut SignalFfiError {
                run_ffi_safe(|| {
                    if data.is_null() {
                        return Err(SignalFfiError::NullPointer);
                    }
                    let data = std::slice::from_raw_parts(data, data_len);
                    box_object(p, $typ::$fn(data))
                })
            }
        }
    };
    ( $typ:ident::$fn:path $(, jni = $jni_name:ident)? ) => {
        paste! {
            bridge_deserialize!($typ::$fn, ffi = [<$typ:snake>]);
        }
    };
}
