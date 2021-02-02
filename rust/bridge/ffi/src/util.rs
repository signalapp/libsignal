//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libc::{c_char, c_uchar, c_uint, size_t};
use libsignal_bridge::ffi::*;
use libsignal_protocol_rust::*;
use std::ffi::CStr;

use aes_gcm_siv::Error as AesGcmSivError;

#[derive(Debug)]
#[repr(C)]
pub enum SignalErrorCode {
    #[allow(dead_code)]
    UnknownError = 1,
    InvalidState = 2,
    InternalError = 3,
    NullParameter = 4,
    InvalidArgument = 5,
    InvalidType = 6,
    InvalidUtf8String = 7,
    InsufficientOutputSize = 8,

    ProtobufError = 10,

    InvalidCiphertext = 20,
    LegacyCiphertextVersion = 21,
    UnknownCiphertextVersion = 22,
    UnrecognizedMessageVersion = 23,
    InvalidMessage = 30,
    SealedSenderSelfSend = 31,

    InvalidKey = 40,
    InvalidSignature = 41,

    FingerprintIdentifierMismatch = 50,
    FingerprintVersionMismatch = 51,
    FingerprintParsingError = 52,

    UntrustedIdentity = 60,

    InvalidKeyIdentifier = 70,

    SessionNotFound = 80,

    DuplicatedMessage = 90,

    CallbackError = 100,
}

impl From<&SignalFfiError> for SignalErrorCode {
    fn from(err: &SignalFfiError) -> Self {
        match err {
            SignalFfiError::NullPointer => SignalErrorCode::NullParameter,
            SignalFfiError::InvalidType => SignalErrorCode::InvalidType,

            SignalFfiError::UnexpectedPanic(_)
            | SignalFfiError::Signal(SignalProtocolError::InternalError(_))
            | SignalFfiError::Signal(SignalProtocolError::FfiBindingError(_))
            | SignalFfiError::Signal(SignalProtocolError::InvalidChainKeyLength(_))
            | SignalFfiError::Signal(SignalProtocolError::InvalidRootKeyLength(_))
            | SignalFfiError::Signal(SignalProtocolError::InvalidCipherCryptographicParameters(
                _,
                _,
            ))
            | SignalFfiError::Signal(SignalProtocolError::InvalidMacKeyLength(_)) => {
                SignalErrorCode::InternalError
            }

            SignalFfiError::InvalidUtf8String => SignalErrorCode::InvalidUtf8String,
            SignalFfiError::InsufficientOutputSize(_, _) => SignalErrorCode::InsufficientOutputSize,

            SignalFfiError::Signal(SignalProtocolError::ProtobufEncodingError(_))
            | SignalFfiError::Signal(SignalProtocolError::ProtobufDecodingError(_)) => {
                SignalErrorCode::ProtobufError
            }

            SignalFfiError::Signal(SignalProtocolError::DuplicatedMessage(_, _)) => {
                SignalErrorCode::DuplicatedMessage
            }

            SignalFfiError::Signal(SignalProtocolError::InvalidPreKeyId)
            | SignalFfiError::Signal(SignalProtocolError::InvalidSignedPreKeyId)
            | SignalFfiError::Signal(SignalProtocolError::InvalidSenderKeyId) => {
                SignalErrorCode::InvalidKeyIdentifier
            }

            SignalFfiError::Signal(SignalProtocolError::SealedSenderSelfSend) => {
                SignalErrorCode::SealedSenderSelfSend
            }

            SignalFfiError::Signal(SignalProtocolError::SignatureValidationFailed) => {
                SignalErrorCode::InvalidSignature
            }

            SignalFfiError::Signal(SignalProtocolError::NoKeyTypeIdentifier)
            | SignalFfiError::Signal(SignalProtocolError::BadKeyType(_))
            | SignalFfiError::Signal(SignalProtocolError::BadKeyLength(_, _))
            | SignalFfiError::AesGcmSiv(AesGcmSivError::InvalidKeySize) => {
                SignalErrorCode::InvalidKey
            }

            SignalFfiError::Signal(SignalProtocolError::SessionNotFound(_)) => {
                SignalErrorCode::SessionNotFound
            }

            SignalFfiError::Signal(SignalProtocolError::FingerprintIdentifierMismatch) => {
                SignalErrorCode::FingerprintIdentifierMismatch
            }

            SignalFfiError::Signal(SignalProtocolError::FingerprintParsingError) => {
                SignalErrorCode::FingerprintParsingError
            }

            SignalFfiError::Signal(SignalProtocolError::FingerprintVersionMismatch(_, _)) => {
                SignalErrorCode::FingerprintVersionMismatch
            }

            SignalFfiError::Signal(SignalProtocolError::CiphertextMessageTooShort(_))
            | SignalFfiError::Signal(SignalProtocolError::InvalidCiphertext)
            | SignalFfiError::AesGcmSiv(AesGcmSivError::InvalidTag) => {
                SignalErrorCode::InvalidCiphertext
            }

            SignalFfiError::Signal(SignalProtocolError::UnrecognizedMessageVersion(_))
            | SignalFfiError::Signal(SignalProtocolError::UnknownSealedSenderVersion(_)) => {
                SignalErrorCode::UnrecognizedMessageVersion
            }

            SignalFfiError::Signal(SignalProtocolError::UnrecognizedCiphertextVersion(_)) => {
                SignalErrorCode::UnknownCiphertextVersion
            }

            SignalFfiError::Signal(SignalProtocolError::InvalidMessage(_))
            | SignalFfiError::Signal(SignalProtocolError::MessageDecryptionFailed(_))
            | SignalFfiError::Signal(SignalProtocolError::InvalidProtobufEncoding)
            | SignalFfiError::Signal(SignalProtocolError::InvalidSealedSenderMessage(_)) => {
                SignalErrorCode::InvalidMessage
            }

            SignalFfiError::Signal(SignalProtocolError::LegacyCiphertextVersion(_)) => {
                SignalErrorCode::LegacyCiphertextVersion
            }

            SignalFfiError::Signal(SignalProtocolError::UntrustedIdentity(_)) => {
                SignalErrorCode::UntrustedIdentity
            }

            SignalFfiError::Signal(SignalProtocolError::InvalidState(_, _))
            | SignalFfiError::Signal(SignalProtocolError::NoSenderKeyState)
            | SignalFfiError::Signal(SignalProtocolError::InvalidSessionStructure) => {
                SignalErrorCode::InvalidState
            }

            SignalFfiError::Signal(SignalProtocolError::InvalidArgument(_))
            | SignalFfiError::AesGcmSiv(_) => SignalErrorCode::InvalidArgument,

            SignalFfiError::Signal(SignalProtocolError::ApplicationCallbackError(_, _)) => {
                SignalErrorCode::CallbackError
            }
        }
    }
}

pub unsafe fn as_slice<'a>(
    input: *const c_uchar,
    input_len: size_t,
) -> Result<&'a [u8], SignalFfiError> {
    if input.is_null() {
        if input_len != 0 {
            return Err(SignalFfiError::NullPointer);
        }
        // We can't just fall through because slice::from_raw_parts still expects a non-null pointer. Reference a dummy buffer instead.
        return Ok(&[]);
    }

    Ok(std::slice::from_raw_parts(input, input_len as usize))
}

pub unsafe fn as_slice_mut<'a>(
    input: *mut c_uchar,
    input_len: size_t,
) -> Result<&'a mut [u8], SignalFfiError> {
    if input.is_null() {
        if input_len != 0 {
            return Err(SignalFfiError::NullPointer);
        }
        // We can't just fall through because slice::from_raw_parts still expects a non-null pointer. Reference a dummy buffer instead.
        return Ok(&mut []);
    }

    Ok(std::slice::from_raw_parts_mut(input, input_len as usize))
}

pub unsafe fn native_handle_cast_mut<T>(handle: *mut T) -> Result<&'static mut T, SignalFfiError> {
    if handle.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    Ok(&mut *handle)
}

pub unsafe fn read_optional_c_string(
    cstr: *const c_char,
) -> Result<Option<String>, SignalFfiError> {
    if cstr.is_null() {
        return Ok(None);
    }

    match CStr::from_ptr(cstr).to_str() {
        Ok(s) => Ok(Some(s.to_owned())),
        Err(_) => Err(SignalFfiError::InvalidUtf8String),
    }
}

pub fn write_uint32_to(
    out: *mut c_uint,
    value: Result<u32, SignalProtocolError>,
) -> Result<(), SignalFfiError> {
    if out.is_null() {
        return Err(SignalFfiError::NullPointer);
    }

    match value {
        Ok(value) => {
            unsafe {
                *out = value;
            }
            Ok(())
        }
        Err(e) => Err(SignalFfiError::Signal(e)),
    }
}

#[macro_export]
macro_rules! ffi_fn_get_new_boxed_obj {
    ( $nm:ident($rt:ty) from $typ:ty, $body:expr ) => {
        #[no_mangle]
        pub unsafe extern "C" fn $nm(
            new_obj: *mut *mut $rt,
            obj: *const $typ,
        ) -> *mut SignalFfiError {
            run_ffi_safe(|| {
                let obj = native_handle_cast::<$typ>(obj)?;
                box_object::<$rt>(new_obj, $body(obj))
            })
        }
    };
}
