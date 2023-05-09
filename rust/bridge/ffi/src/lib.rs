//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![warn(clippy::unwrap_used)]

use futures_util::FutureExt;
use libc::{c_char, c_uchar, c_uint, size_t};
use libsignal_bridge::ffi::*;
use libsignal_protocol::*;
use std::convert::TryFrom;
use std::ffi::{c_void, CString};
use std::panic::AssertUnwindSafe;

pub mod logging;
mod util;

use crate::util::*;

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
pub unsafe extern "C" fn signal_free_buffer(buf: *const c_uchar, buf_len: size_t) {
    if buf.is_null() {
        return;
    }
    drop(Box::from_raw(std::slice::from_raw_parts_mut(
        buf as *mut c_uchar,
        buf_len,
    )));
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_get_message(
    err: *const SignalFfiError,
    out: *mut *const c_char,
) -> *mut SignalFfiError {
    let result = (|| {
        if err.is_null() {
            return Err(SignalFfiError::NullPointer);
        }
        let msg = format!("{}", *err);
        write_result_to(out, msg)
    })();

    match result {
        Ok(()) => std::ptr::null_mut(),
        Err(e) => Box::into_raw(Box::new(e)),
    }
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_get_address(
    err: *const SignalFfiError,
    out: *mut *mut ProtocolAddress,
) -> *mut SignalFfiError {
    let err = AssertUnwindSafe(err);
    run_ffi_safe(|| {
        let err = err.as_ref().ok_or(SignalFfiError::NullPointer)?;
        match err {
            SignalFfiError::Signal(SignalProtocolError::InvalidRegistrationId(addr, _value)) => {
                write_result_to(out, addr.clone())?;
            }
            _ => {
                return Err(SignalFfiError::Signal(
                    SignalProtocolError::InvalidArgument(format!(
                        "cannot get address from error ({})",
                        err
                    )),
                ));
            }
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_get_uuid(
    err: *const SignalFfiError,
    out: *mut [u8; 16],
) -> *mut SignalFfiError {
    let err = AssertUnwindSafe(err);
    run_ffi_safe(|| {
        let err = err.as_ref().ok_or(SignalFfiError::NullPointer)?;
        match err {
            SignalFfiError::Signal(SignalProtocolError::InvalidSenderKeySession {
                distribution_id,
            }) => {
                write_result_to(out, *distribution_id.as_bytes())?;
            }
            _ => {
                return Err(SignalFfiError::Signal(
                    SignalProtocolError::InvalidArgument(format!(
                        "cannot get address from error ({})",
                        err
                    )),
                ));
            }
        }
        Ok(())
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_get_type(err: *const SignalFfiError) -> u32 {
    match err.as_ref() {
        Some(err) => {
            let code: SignalErrorCode = err.into();
            code as u32
        }
        None => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_free(err: *mut SignalFfiError) {
    if !err.is_null() {
        let _boxed_err = Box::from_raw(err);
    }
}

#[no_mangle]
pub unsafe extern "C" fn signal_identitykeypair_deserialize(
    private_key: *mut *mut PrivateKey,
    public_key: *mut *mut PublicKey,
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
    trust_root: *const PublicKey,
    timestamp: u64,
    local_e164: *const c_char,
    local_uuid: *const c_char,
    local_device_id: c_uint,
    session_store: *const FfiSessionStoreStruct,
    identity_store: *const FfiIdentityKeyStoreStruct,
    prekey_store: *const FfiPreKeyStoreStruct,
    signed_prekey_store: *const FfiSignedPreKeyStoreStruct,
    ctx: *mut c_void,
) -> *mut SignalFfiError {
    run_ffi_safe(|| {
        let mut kyber_pre_key_store = InMemKyberPreKeyStore::new();
        let ctext = ctext.as_slice()?;
        let trust_root = native_handle_cast::<PublicKey>(trust_root)?;
        let mut identity_store = identity_store.as_ref().ok_or(SignalFfiError::NullPointer)?;
        let mut session_store = session_store.as_ref().ok_or(SignalFfiError::NullPointer)?;
        let mut prekey_store = prekey_store.as_ref().ok_or(SignalFfiError::NullPointer)?;
        let mut signed_prekey_store = signed_prekey_store
            .as_ref()
            .ok_or(SignalFfiError::NullPointer)?;

        let local_e164 = Option::convert_from(local_e164)?;
        let local_uuid = Option::convert_from(local_uuid)?.ok_or(SignalFfiError::NullPointer)?;

        let decrypted = sealed_sender_decrypt(
            ctext,
            trust_root,
            timestamp,
            local_e164,
            local_uuid,
            local_device_id.into(),
            &mut identity_store,
            &mut session_store,
            &mut prekey_store,
            &mut signed_prekey_store,
            &mut kyber_pre_key_store,
            Some(ctx),
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
