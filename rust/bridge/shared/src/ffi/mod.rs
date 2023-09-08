//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_protocol::*;
use std::ffi::CString;

#[macro_use]
mod convert;
pub use convert::*;

mod error;
pub use error::*;

mod io;
pub use io::*;

mod storage;
pub use storage::*;

#[derive(Debug)]
pub struct NullPointerError;

#[repr(C)]
pub struct BorrowedSliceOf<T> {
    base: *const T,
    length: usize,
}

impl<T> BorrowedSliceOf<T> {
    pub unsafe fn as_slice(&self) -> Result<&[T], NullPointerError> {
        if self.base.is_null() {
            if self.length != 0 {
                return Err(NullPointerError);
            }
            // We can't just fall through because slice::from_raw_parts still expects a non-null pointer. Reference a dummy buffer instead.
            return Ok(&[]);
        }

        Ok(std::slice::from_raw_parts(self.base, self.length))
    }
}

#[repr(C)]
pub struct BorrowedMutableSliceOf<T> {
    base: *mut T,
    length: usize,
}

impl<T> BorrowedMutableSliceOf<T> {
    pub unsafe fn as_slice_mut(&mut self) -> Result<&mut [T], NullPointerError> {
        if self.base.is_null() {
            if self.length != 0 {
                return Err(NullPointerError);
            }
            // We can't just fall through because slice::from_raw_parts still expects a non-null pointer. Reference a dummy buffer instead.
            return Ok(&mut []);
        }

        Ok(std::slice::from_raw_parts_mut(self.base, self.length))
    }
}

#[repr(C)]
pub struct OwnedBufferOf<T> {
    base: *mut T,
    length: usize,
}

impl<T> From<Box<[T]>> for OwnedBufferOf<T> {
    fn from(value: Box<[T]>) -> Self {
        let raw = unsafe { Box::into_raw(value).as_mut().expect("just created") };
        Self {
            base: raw.as_mut_ptr(),
            length: raw.len(),
        }
    }
}

#[inline(always)]
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
                        drop(Box::from_raw(p));
                    }
                    Ok(())
                })
            }
        }
    };
}
