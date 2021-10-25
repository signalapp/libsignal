//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libc::{c_uchar, size_t};
use libsignal_protocol::*;
use std::ffi::CString;

#[macro_use]
mod convert;
pub use convert::*;

mod error;
pub use error::*;

mod storage;
pub use storage::*;

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

pub unsafe fn native_handle_cast<T>(handle: *const T) -> Result<&'static T, SignalFfiError> {
    if handle.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    Ok(&*(handle))
}

pub unsafe fn native_handle_cast_mut<T>(handle: *mut T) -> Result<&'static mut T, SignalFfiError> {
    if handle.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    Ok(&mut *handle)
}

pub unsafe fn write_result_to<T: ResultTypeInfo>(
    ptr: *mut T::ResultType,
    value: T,
) -> SignalFfiResult<()> {
    if ptr.is_null() {
        return Err(SignalFfiError::NullPointer);
    }
    *ptr = value.convert_into()?;
    Ok(())
}

pub unsafe fn write_bytearray_to<T: Into<Box<[u8]>>>(
    out: *mut *const c_uchar,
    out_len: *mut size_t,
    value: Option<T>,
) -> Result<(), SignalFfiError> {
    if out.is_null() || out_len.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    if let Some(value) = value {
        let value: Box<[u8]> = value.into();

        *out_len = value.len();
        let mem = Box::into_raw(value);
        *out = (*mem).as_ptr();
    } else {
        *out = std::ptr::null();
        *out_len = 0;
    }

    Ok(())
}

/// Used by [`bridge_handle`](crate::support::bridge_handle).
///
/// Not intended to be invoked directly.
macro_rules! ffi_bridge_destroy {
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
}
