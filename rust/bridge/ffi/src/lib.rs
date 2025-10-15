//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![warn(clippy::unwrap_used)]

use std::ffi::{CString, c_char, c_uchar};

use libsignal_bridge::ffi::{self, *};
use libsignal_bridge::{IllegalArgumentError, ffi_arg_type};
use libsignal_bridge_macros::bridge_fn;
#[cfg(feature = "libsignal-bridge-testing")]
#[allow(unused_imports)]
use libsignal_bridge_testing::*;

pub mod error;
pub mod logging;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_print_ptr(p: *const std::ffi::c_void) {
    println!("In rust that's {p:?}");
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_free_string(buf: *const c_char) {
    if buf.is_null() {
        return;
    }
    drop(unsafe { CString::from_raw(buf as _) });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_free_buffer(buf: *const c_uchar, buf_len: usize) {
    if buf.is_null() {
        return;
    }
    drop(unsafe {
        Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            buf as *mut c_uchar,
            buf_len,
        ))
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_free_list_of_strings(buffer: OwnedBufferOf<CStringPtr>) {
    let strings = unsafe { buffer.into_box() };
    for &s in &*strings {
        unsafe { signal_free_string(s) };
    }
    drop(strings);
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_free_list_of_register_response_badges(
    buffer: OwnedBufferOf<FfiRegisterResponseBadge>,
) {
    for badge in unsafe { buffer.into_box() } {
        let FfiRegisterResponseBadge {
            id,
            visible,
            expiration_secs,
        } = badge;
        unsafe { signal_free_string(id) };
        let _: (bool, f64) = (visible, expiration_secs);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_free_lookup_response_entry_list(
    buffer: OwnedBufferOf<crate::FfiCdsiLookupResponseEntry>,
) {
    drop(unsafe { buffer.into_box() })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_free_bytestring_array(array: BytestringArray) {
    drop(unsafe { array.into_boxed_parts() })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_free_list_of_service_ids(
    buffer: OwnedBufferOf<libsignal_core::ServiceIdFixedWidthBinaryBytes>,
) {
    drop(unsafe { buffer.into_box() })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_free_list_of_mismatched_device_errors(
    buffer: OwnedBufferOf<FfiMismatchedDevicesError>,
) {
    let entries = unsafe { buffer.into_box() };
    for mut entry in entries {
        unsafe { entry.free_buffers() };
    }
    // The for-in loop already consumed 'entries'; our work is done.
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_error_free(err: *mut SignalFfiError) {
    if !err.is_null() {
        let _boxed_err = unsafe { Box::from_raw(err) };
    }
}

#[bridge_fn(jni = false, node = false)]
fn hex_encode(output: &mut [u8], input: &[u8]) -> Result<(), IllegalArgumentError> {
    hex::encode_to_slice(input, output)
        .map_err(|_| IllegalArgumentError::new("output buffer too small"))
}
