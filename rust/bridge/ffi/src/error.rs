//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ffi::{c_char, c_uchar};
use std::panic::AssertUnwindSafe;

use libsignal_bridge::ffi::{
    self, NullPointerError, OwnedBufferOf, SignalFfiError, run_ffi_safe, write_result_to,
};
use libsignal_bridge::{IllegalArgumentError, ffi_arg_type, ffi_result_type};
use libsignal_bridge_macros::bridge_fn;
use libsignal_core::ProtocolAddress;

// Not using bridge_fn because it also handles `NULL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_error_get_type(err: *const SignalFfiError) -> u32 {
    match unsafe { err.as_ref() } {
        Some(err) => err.code() as u32,
        None => 0,
    }
}

#[bridge_fn(jni = false, node = false)]
fn Error_GetMessage(err: &SignalFfiError) -> String {
    err.to_string()
}

#[bridge_fn(jni = false, node = false)]
fn Error_GetAddress(err: &SignalFfiError) -> Result<ProtocolAddress, IllegalArgumentError> {
    err.provide_address()
        .map_err(|_| IllegalArgumentError::new(format!("cannot get address from error ({err})")))
}

#[bridge_fn(jni = false, node = false)]
fn Error_GetUuid(err: &SignalFfiError) -> Result<[u8; 16], IllegalArgumentError> {
    Ok(err
        .provide_uuid()
        .map_err(|_| IllegalArgumentError::new(format!("cannot get UUID from error ({err})")))?
        .into_bytes())
}

// Not using bridge_fn because it returns multiple values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_error_get_invalid_protocol_address(
    name_out: *mut *const c_char,
    device_id_out: *mut u32,
    err: *const SignalFfiError,
) -> *mut SignalFfiError {
    let err = AssertUnwindSafe(err);
    run_ffi_safe(|| {
        let err = unsafe { err.as_ref().ok_or(NullPointerError)? };
        let (name, device_id) = err.provide_invalid_address().map_err(|_| {
            IllegalArgumentError::new(format!("cannot get address from error ({err})"))
        })?;
        unsafe {
            write_result_to(name_out, name)?;
            write_result_to(device_id_out, device_id)?;
        }
        Ok(())
    })
}

#[bridge_fn(jni = false, node = false)]
fn Error_GetUnknownFields(err: &SignalFfiError) -> Result<Box<[String]>, IllegalArgumentError> {
    Ok(err
        .provide_unknown_fields()
        .map_err(|_| {
            IllegalArgumentError::new(format!("cannot get unknown_fields from error ({err})"))
        })?
        .into_boxed_slice())
}

// Not using bridge_fn because it returns multiple values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_error_get_registration_error_not_deliverable(
    out_reason: *mut *const c_char,
    out_permanent: *mut bool,
    err: *const SignalFfiError,
) -> *mut SignalFfiError {
    let err = AssertUnwindSafe(err);
    run_ffi_safe(|| {
        let err = unsafe { err.as_ref().ok_or(NullPointerError)? };

        let libsignal_net_chat::api::registration::VerificationCodeNotDeliverable {
            reason,
            permanent_failure,
        } = err
            .provide_registration_code_not_deliverable()
            .map_err(|_| {
                IllegalArgumentError::new(format!(
                    "cannot get registration error from error ({err})"
                ))
            })?;
        unsafe {
            write_result_to(out_reason, reason.as_str())?;
            write_result_to(out_permanent, *permanent_failure)?;
        }
        Ok(())
    })
}

// Not using bridge_fn because it returns multiple values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_error_get_registration_lock(
    out_time_remaining_seconds: *mut u64,
    out_svr2_username: *mut *const c_char,
    out_svr2_password: *mut *const c_char,
    err: *const SignalFfiError,
) -> *mut SignalFfiError {
    let err = AssertUnwindSafe(err);
    run_ffi_safe(|| {
        let err = unsafe { err.as_ref().ok_or(NullPointerError)? };

        let libsignal_net_chat::api::registration::RegistrationLock {
            time_remaining,
            svr2_credentials:
                libsignal_net::auth::Auth {
                    username: svr2_username,
                    password: svr2_password,
                },
        } = err.provide_registration_lock().map_err(|_| {
            IllegalArgumentError::new(format!("cannot get registration error from error ({err})"))
        })?;
        unsafe {
            write_result_to(out_time_remaining_seconds, time_remaining.as_secs())?;
            write_result_to(out_svr2_username, svr2_username.as_str())?;
            write_result_to(out_svr2_password, svr2_password.as_str())?;
        }
        Ok(())
    })
}

#[bridge_fn(jni = false, node = false)]
fn Error_GetOurFingerprintVersion(err: &SignalFfiError) -> Result<u32, IllegalArgumentError> {
    Ok(err
        .provide_fingerprint_versions()
        .map_err(|_| {
            IllegalArgumentError::new(format!(
                "cannot get fingerprint_versions from error ({err})"
            ))
        })?
        .ours)
}

#[bridge_fn(jni = false, node = false)]
fn Error_GetTheirFingerprintVersion(err: &SignalFfiError) -> Result<u32, IllegalArgumentError> {
    Ok(err
        .provide_fingerprint_versions()
        .map_err(|_| {
            IllegalArgumentError::new(format!(
                "cannot get fingerprint_versions from error ({err})"
            ))
        })?
        .theirs)
}

#[bridge_fn(jni = false, node = false)]
fn Error_GetRetryAfterSeconds(err: &SignalFfiError) -> Result<u32, IllegalArgumentError> {
    err.provide_retry_after_seconds().map_err(|_| {
        IllegalArgumentError::new(format!("cannot get retry_after_seconds from error ({err})"))
    })
}

#[bridge_fn(jni = false, node = false)]
fn Error_GetTriesRemaining(err: &SignalFfiError) -> Result<u32, IllegalArgumentError> {
    err.provide_tries_remaining().map_err(|_| {
        IllegalArgumentError::new(format!("cannot get tries_remaining from error ({err})"))
    })
}

// Not using bridge_fn because it returns multiple values.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal_error_get_rate_limit_challenge(
    out_token: *mut *const c_char,
    out_options: *mut OwnedBufferOf<c_uchar>,
    err: *const SignalFfiError,
) -> *mut SignalFfiError {
    let err = AssertUnwindSafe(err);
    run_ffi_safe(|| {
        let err = unsafe { err.as_ref().ok_or(NullPointerError)? };

        let libsignal_net_chat::api::RateLimitChallenge { token, options } =
            err.provide_rate_limit_challenge().map_err(|_| {
                IllegalArgumentError::new(format!(
                    "cannot get rate limit challenge error from error ({err})"
                ))
            })?;
        unsafe { write_result_to(out_token, token.as_str())? };
        unsafe { write_result_to(out_options, options.as_slice())? };
        Ok(())
    })
}
