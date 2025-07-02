//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![warn(clippy::unwrap_used)]

use std::ffi::{c_char, c_uchar, CString};

use libsignal_bridge::ffi::*;
#[cfg(feature = "libsignal-bridge-testing")]
#[allow(unused_imports)]
use libsignal_bridge_testing::*;
use libsignal_protocol::*;

pub mod error;
pub mod logging;

#[no_mangle]
pub unsafe extern "C" fn signal_print_ptr(p: *const std::ffi::c_void) {
    println!("In rust that's {p:?}");
}

#[no_mangle]
pub unsafe extern "C" fn signal_free_string(buf: *const c_char) {
    if buf.is_null() {
        return;
    }
    drop(CString::from_raw(buf as _));
}

#[no_mangle]
pub unsafe extern "C" fn signal_free_buffer(buf: *const c_uchar, buf_len: usize) {
    if buf.is_null() {
        return;
    }
    drop(Box::from_raw(std::slice::from_raw_parts_mut(
        buf as *mut c_uchar,
        buf_len,
    )));
}

#[no_mangle]
pub unsafe extern "C" fn signal_free_list_of_strings(buffer: OwnedBufferOf<CStringPtr>) {
    let strings = buffer.into_box();
    for &s in &*strings {
        signal_free_string(s);
    }
    drop(strings);
}

#[no_mangle]
pub unsafe extern "C" fn signal_free_list_of_register_response_badges(
    buffer: OwnedBufferOf<FfiRegisterResponseBadge>,
) {
    for badge in buffer.into_box() {
        let FfiRegisterResponseBadge {
            id,
            visible,
            expiration_secs,
        } = badge;
        signal_free_string(id);
        let _: (bool, f64) = (visible, expiration_secs);
    }
}

#[no_mangle]
pub unsafe extern "C" fn signal_free_lookup_response_entry_list(
    buffer: OwnedBufferOf<crate::FfiCdsiLookupResponseEntry>,
) {
    drop(buffer.into_box())
}

#[no_mangle]
pub unsafe extern "C" fn signal_free_bytestring_array(array: BytestringArray) {
    drop(array.into_boxed_parts())
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_free(err: *mut SignalFfiError) {
    if !err.is_null() {
        let _boxed_err = Box::from_raw(err);
    }
}

#[no_mangle]
pub unsafe extern "C" fn signal_identitykeypair_deserialize(
    private_key: *mut MutPointer<PrivateKey>,
    public_key: *mut MutPointer<PublicKey>,
    input: BorrowedSliceOf<c_uchar>,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let input = input.as_slice()?;
        let identity_key_pair = IdentityKeyPair::try_from(input)?;
        write_result_to(public_key, *identity_key_pair.public_key())?;
        write_result_to(private_key, *identity_key_pair.private_key())?;
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_hex_encode(
    output: *mut c_char,
    output_len: usize,
    input: *const u8,
    input_len: usize,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        if input_len == 0 {
            return Ok(());
        }
        if input_len > output_len / 2 {
            // We check this early because an output buffer of {NULL, 0} is *valid*, just too small
            // for anything but a zero-length input, while std::slice::from_raw_parts_mut requires a
            // non-null base pointer.
            return Err(SignalProtocolError::InvalidArgument(
                "output buffer too small".to_string(),
            )
            .into());
        }
        if input.is_null() || output.is_null() {
            return Err(NullPointerError.into());
        }
        let output = std::slice::from_raw_parts_mut(output, output_len);
        let output = zerocopy::IntoBytes::as_mut_bytes(output);
        let input = std::slice::from_raw_parts(input, input_len);
        hex::encode_to_slice(input, output).expect("checked above");
        Ok(())
    })
}
