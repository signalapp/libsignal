//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod error;
pub use error::*;

pub(crate) use paste::paste;

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
