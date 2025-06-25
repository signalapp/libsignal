//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![allow(clippy::missing_safety_doc)]
#![warn(clippy::unwrap_used)]

use std::ffi::{c_char, c_uchar, CString};
use std::panic::AssertUnwindSafe;

use libsignal_bridge::ffi::*;
#[cfg(feature = "libsignal-bridge-testing")]
#[allow(unused_imports)]
use libsignal_bridge_testing::*;
use libsignal_core::try_scoped;
use libsignal_protocol::*;
use paste::paste;

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
pub unsafe extern "C" fn signal_error_get_message(
    err: *const SignalFfiError,
    out: *mut *const c_char,
) -> *mut SignalFfiError {
    let result = try_scoped(|| {
        let err = err.as_ref().ok_or(NullPointerError)?;
        write_result_to(out, err.to_string())
    });

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
            SignalProtocolError::InvalidArgument(format!("cannot get address from error ({err})"))
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
            SignalProtocolError::InvalidArgument(format!("cannot get UUID from error ({err})"))
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
pub unsafe extern "C" fn signal_error_get_invalid_protocol_address(
    err: *const SignalFfiError,
    name_out: *mut *const c_char,
    device_id_out: *mut u32,
) -> *mut SignalFfiError {
    let err = AssertUnwindSafe(err);
    run_ffi_safe(|| {
        let err = err.as_ref().ok_or(NullPointerError)?;
        let (name, device_id) = err.provide_invalid_address().map_err(|_| {
            SignalProtocolError::InvalidArgument(format!("cannot get address from error ({err})"))
        })?;
        write_result_to(name_out, name)?;
        write_result_to(device_id_out, device_id)
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
                    "cannot get unknown_fields from error ({err})"
                ))
            })?
            .into_boxed_slice();
        write_result_to(out, value)
    })
}

#[no_mangle]
pub unsafe extern "C" fn signal_error_get_registration_error_not_deliverable(
    err: *const SignalFfiError,
    out_reason: *mut *const c_char,
    out_permanent: *mut bool,
) -> *mut SignalFfiError {
    let err = AssertUnwindSafe(err);
    run_ffi_safe(|| {
        let err = err.as_ref().ok_or(NullPointerError)?;

        let libsignal_net_chat::api::registration::VerificationCodeNotDeliverable {
            reason,
            permanent_failure,
        } = err
            .provide_registration_code_not_deliverable()
            .map_err(|_| {
                SignalProtocolError::InvalidArgument(format!(
                    "cannot get registration error from error ({err})"
                ))
            })?;
        write_result_to(out_reason, reason.as_str())?;
        write_result_to(out_permanent, *permanent_failure)?;
        Ok(())
    })
}
#[no_mangle]
pub unsafe extern "C" fn signal_error_get_registration_lock(
    err: *const SignalFfiError,
    out_time_remaining_seconds: *mut u64,
    out_svr2_username: *mut *const c_char,
    out_svr2_password: *mut *const c_char,
) -> *mut SignalFfiError {
    let err = AssertUnwindSafe(err);
    run_ffi_safe(|| {
        let err = err.as_ref().ok_or(NullPointerError)?;

        let libsignal_net_chat::api::registration::RegistrationLock {
            time_remaining,
            svr2_credentials:
                libsignal_net::auth::Auth {
                    username: svr2_username,
                    password: svr2_password,
                },
        } = err.provide_registration_lock().map_err(|_| {
            SignalProtocolError::InvalidArgument(format!(
                "cannot get registration error from error ({err})"
            ))
        })?;
        write_result_to(out_time_remaining_seconds, time_remaining.as_secs())?;
        write_result_to(out_svr2_username, svr2_username.as_str())?;
        write_result_to(out_svr2_password, svr2_password.as_str())?;
        Ok(())
    })
}

macro_rules! get_named_u32_from_err_impl {
    ($name:ident) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [< signal_error_get_ $name >](
                err: *const SignalFfiError,
                out: *mut u32,
            ) -> *mut SignalFfiError {
                let err = AssertUnwindSafe(err);
                run_ffi_safe(|| {
                    let err = err.as_ref().ok_or(NullPointerError)?;
                    let value = err.[< provide_ $name >]().map_err(|_| {
                        SignalProtocolError::InvalidArgument(format!(
                            "cannot get $name from error ({err})"
                        ))
                    })?;
                    write_result_to(out, value)
                })
            }
        }
    };
    // Similar to the above, only adds an extra .map(...) step to extract the final u32
    ($name:ident, $field:ident, $c_name:ident) => {
        paste! {
            #[no_mangle]
            pub unsafe extern "C" fn [< signal_error_get_ $c_name >](
                err: *const SignalFfiError,
                out: *mut u32,
            ) -> *mut SignalFfiError {
                let err = AssertUnwindSafe(err);
                run_ffi_safe(|| {
                    let err = err.as_ref().ok_or(NullPointerError)?;
                    let value = err.[< provide_ $name >]()
                        .map(|x| x.$field)
                        .map_err(|_| {
                            SignalProtocolError::InvalidArgument(format!(
                                "cannot get $name from error ({err})"
                        ))}
                    )?;
                    write_result_to(out, value)
                })
            }
        }
    };
}

get_named_u32_from_err_impl!(fingerprint_versions, ours, our_fingerprint_version);
get_named_u32_from_err_impl!(fingerprint_versions, theirs, their_fingerprint_version);
get_named_u32_from_err_impl!(retry_after_seconds);
get_named_u32_from_err_impl!(tries_remaining);

#[no_mangle]
pub unsafe extern "C" fn signal_error_get_rate_limit_challenge(
    err: *const SignalFfiError,
    out_token: *mut *const c_char,
    out_options: *mut OwnedBufferOf<c_uchar>,
) -> *mut SignalFfiError {
    let err = AssertUnwindSafe(err);
    run_ffi_safe(|| {
        let err = err.as_ref().ok_or(NullPointerError)?;

        let libsignal_net_chat::api::RateLimitChallenge { token, options } =
            err.provide_rate_limit_challenge().map_err(|_| {
                SignalProtocolError::InvalidArgument(format!(
                    "cannot get rate limit challenge error from error ({err})"
                ))
            })?;
        write_result_to(out_token, token.as_str())?;
        write_result_to(out_options, options.as_slice())?;
        Ok(())
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
