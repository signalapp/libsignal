//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![warn(clippy::unwrap_used)]

use std::ffi::{c_char, c_uchar, c_uint, CString};
use std::panic::AssertUnwindSafe;

use futures_util::FutureExt;
use libsignal_bridge::ffi::*;
#[cfg(feature = "libsignal-bridge-testing")]
#[allow(unused_imports)]
use libsignal_bridge_testing::*;
use libsignal_protocol::*;

pub mod logging;

#[no_mangle]
pub unsafe extern "C" fn signal_print_ptr(p: *const std::ffi::c_void) {
    println!("In rust that's {:?}", p);
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
pub unsafe extern "C" fn signal_error_get_message(
    err: *const SignalFfiError,
    out: *mut *const c_char,
) -> *mut SignalFfiError {
    let result = (|| {
        let err = err.as_ref().ok_or(NullPointerError)?;
        write_result_to(out, err.to_string())
    })();

    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => Box::into_raw(Box::new(e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_get_address(
    err: *const SignalFfiError,
    out: *mut MutPointer<ProtocolAddress>,
) -> *mut SignalFfiError {
    let err = AssertUnwindSafe(err);
    run_ffi_safe(|| {
        let err = err.as_ref().ok_or(NullPointerError)?;
        let value = err.provide_address().map_err(|_| {
            SignalProtocolError::InvalidArgument(format!("cannot get address from error ({})", err))
        })?;
        write_result_to(out, value)
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_get_uuid(
    err: *const SignalFfiError,
    out: *mut [u8; 16],
) -> *mut SignalFfiError {
    let err = AssertUnwindSafe(err);
    run_ffi_safe(|| {
        let err = err.as_ref().ok_or(NullPointerError)?;
        let value = err.provide_uuid().map_err(|_| {
            SignalProtocolError::InvalidArgument(format!("cannot get UUID from error ({})", err))
        })?;
        write_result_to(out, value.into_bytes())
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_get_type(err: *const SignalFfiError) -> u32 {
    match err.as_ref() {
        Some(err) => err.code() as u32,
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_get_retry_after_seconds(
    err: *const SignalFfiError,
    out: *mut u32,
) -> *mut SignalFfiError {
    let err = AssertUnwindSafe(err);
    run_ffi_safe(|| {
        let err = err.as_ref().ok_or(NullPointerError)?;
        let value = err.provide_retry_after_seconds().map_err(|_| {
            SignalProtocolError::InvalidArgument(format!(
                "cannot get retry_after_seconds from error ({})",
                err
            ))
        })?;
        write_result_to(out, value)
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_get_tries_remaining(
    err: *const SignalFfiError,
    out: *mut u32,
) -> *mut SignalFfiError {
    let err = AssertUnwindSafe(err);
    run_ffi_safe(|| {
        let err = err.as_ref().ok_or(NullPointerError)?;
        let value = err.provide_tries_remaining().map_err(|_| {
            SignalProtocolError::InvalidArgument(format!(
                "cannot get tries_remaining from error ({})",
                err
            ))
        })?;
        write_result_to(out, value)
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_get_unknown_fields(
    err: *const SignalFfiError,
    out: *mut StringArray,
) -> *mut SignalFfiError {
    let err = AssertUnwindSafe(err);
    run_ffi_safe(|| {
        let err = err.as_ref().ok_or(NullPointerError)?;
        let value = err
            .provide_unknown_fields()
            .map_err(|_| {
                SignalProtocolError::InvalidArgument(format!(
                    "cannot get unknown_fields from error ({})",
                    err
                ))
            })?
            .into_boxed_slice();
        write_result_to(out, value)
    })
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
pub unsafe extern "C" fn signal_sealed_session_cipher_decrypt(
    out: *mut OwnedBufferOf<c_uchar>,
    sender_e164: *mut *const c_char,
    sender_uuid: *mut *const c_char,
    sender_device_id: *mut u32,
    ctext: BorrowedSliceOf<c_uchar>,
    trust_root: ConstPointer<PublicKey>,
    timestamp: u64,
    local_e164: *const c_char,
    local_uuid: *const c_char,
    local_device_id: c_uint,
    session_store: ConstPointer<FfiSessionStoreStruct>,
    identity_store: ConstPointer<FfiIdentityKeyStoreStruct>,
    prekey_store: ConstPointer<FfiPreKeyStoreStruct>,
    signed_prekey_store: ConstPointer<FfiSignedPreKeyStoreStruct>,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let mut kyber_pre_key_store = InMemKyberPreKeyStore::new();
        let ctext = ctext.as_slice()?;
        let trust_root = native_handle_cast::<PublicKey>(trust_root.into_inner())?;
        let mut identity_store = identity_store
            .into_inner()
            .as_ref()
            .ok_or(NullPointerError)?;
        let mut session_store = session_store
            .into_inner()
            .as_ref()
            .ok_or(NullPointerError)?;
        let mut prekey_store = prekey_store.into_inner().as_ref().ok_or(NullPointerError)?;
        let signed_prekey_store = signed_prekey_store
            .into_inner()
            .as_ref()
            .ok_or(NullPointerError)?;

        let local_e164 = Option::convert_from(local_e164)?;
        let local_uuid = Option::convert_from(local_uuid)?.ok_or(NullPointerError)?;

        let decrypted = sealed_sender_decrypt(
            ctext,
            trust_root,
            Timestamp::from_epoch_millis(timestamp),
            local_e164,
            local_uuid,
            local_device_id.into(),
            &mut identity_store,
            &mut session_store,
            &mut prekey_store,
            &signed_prekey_store,
            &mut kyber_pre_key_store,
        )
        .now_or_never()
        .expect("synchronous")?;

        write_result_to(sender_e164, decrypted.sender_e164)?;
        write_result_to(sender_uuid, decrypted.sender_uuid)?;
        write_result_to(sender_device_id, u32::from(decrypted.device_id))?;
        write_result_to(out, decrypted.message)?;
        Ok(())
    })
}
