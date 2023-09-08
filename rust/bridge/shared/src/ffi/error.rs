//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryFrom;
use std::fmt;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};

use attest::hsm_enclave::Error as HsmEnclaveError;
use attest::sgx_session::Error as SgxError;
use device_transfer::Error as DeviceTransferError;
use libsignal_protocol::*;
use signal_crypto::Error as SignalCryptoError;
use signal_pin::Error as PinError;
use usernames::{UsernameError, UsernameLinkError};
use zkgroup::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure};

use crate::support::describe_panic;

use super::NullPointerError;

/// The top-level error type (opaquely) returned to C clients when something goes wrong.
#[derive(Debug)]
pub enum SignalFfiError {
    Signal(SignalProtocolError),
    DeviceTransfer(DeviceTransferError),
    HsmEnclave(HsmEnclaveError),
    Sgx(SgxError),
    Pin(PinError),
    SignalCrypto(SignalCryptoError),
    ZkGroupVerificationFailure(ZkGroupVerificationFailure),
    ZkGroupDeserializationFailure(ZkGroupDeserializationFailure),
    UsernameError(UsernameError),
    UsernameLinkError(UsernameLinkError),
    Io(IoError),
    #[cfg(feature = "signal-media")]
    MediaSanitizeParse(signal_media::sanitize::ParseErrorReport),
    NullPointer,
    InvalidUtf8String,
    UnexpectedPanic(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
}

impl fmt::Display for SignalFfiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignalFfiError::Signal(s) => write!(f, "{}", s),
            SignalFfiError::DeviceTransfer(c) => {
                write!(f, "Device transfer operation failed: {}", c)
            }
            SignalFfiError::HsmEnclave(e) => {
                write!(f, "HSM enclave operation failed: {}", e)
            }
            SignalFfiError::Sgx(e) => {
                write!(f, "SGX operation failed: {}", e)
            }
            SignalFfiError::SignalCrypto(c) => {
                write!(f, "Cryptographic operation failed: {}", c)
            }
            SignalFfiError::Pin(e) => write!(f, "{}", e),
            SignalFfiError::ZkGroupVerificationFailure(e) => write!(f, "{}", e),
            SignalFfiError::ZkGroupDeserializationFailure(e) => write!(f, "{}", e),
            SignalFfiError::UsernameError(e) => write!(f, "{}", e),
            SignalFfiError::UsernameLinkError(e) => write!(f, "{}", e),
            SignalFfiError::Io(e) => write!(f, "IO error: {}", e),
            #[cfg(feature = "signal-media")]
            SignalFfiError::MediaSanitizeParse(e) => {
                write!(f, "Media sanitizer failed to parse media file: {}", e)
            }
            SignalFfiError::NullPointer => write!(f, "null pointer"),
            SignalFfiError::InvalidUtf8String => write!(f, "invalid UTF8 string"),
            SignalFfiError::UnexpectedPanic(e) => {
                write!(f, "unexpected panic: {}", describe_panic(e))
            }
        }
    }
}

impl From<SignalProtocolError> for SignalFfiError {
    fn from(e: SignalProtocolError) -> SignalFfiError {
        SignalFfiError::Signal(e)
    }
}

impl From<DeviceTransferError> for SignalFfiError {
    fn from(e: DeviceTransferError) -> SignalFfiError {
        SignalFfiError::DeviceTransfer(e)
    }
}

impl From<HsmEnclaveError> for SignalFfiError {
    fn from(e: HsmEnclaveError) -> SignalFfiError {
        SignalFfiError::HsmEnclave(e)
    }
}

impl From<SgxError> for SignalFfiError {
    fn from(e: SgxError) -> SignalFfiError {
        SignalFfiError::Sgx(e)
    }
}

impl From<PinError> for SignalFfiError {
    fn from(e: PinError) -> SignalFfiError {
        SignalFfiError::Pin(e)
    }
}

impl From<SignalCryptoError> for SignalFfiError {
    fn from(e: SignalCryptoError) -> SignalFfiError {
        SignalFfiError::SignalCrypto(e)
    }
}

impl From<ZkGroupVerificationFailure> for SignalFfiError {
    fn from(e: ZkGroupVerificationFailure) -> SignalFfiError {
        SignalFfiError::ZkGroupVerificationFailure(e)
    }
}

impl From<ZkGroupDeserializationFailure> for SignalFfiError {
    fn from(e: ZkGroupDeserializationFailure) -> SignalFfiError {
        SignalFfiError::ZkGroupDeserializationFailure(e)
    }
}

impl From<UsernameError> for SignalFfiError {
    fn from(e: UsernameError) -> SignalFfiError {
        SignalFfiError::UsernameError(e)
    }
}

impl From<UsernameLinkError> for SignalFfiError {
    fn from(e: UsernameLinkError) -> SignalFfiError {
        SignalFfiError::UsernameLinkError(e)
    }
}

impl From<IoError> for SignalFfiError {
    fn from(e: IoError) -> SignalFfiError {
        Self::Io(e)
    }
}

#[cfg(feature = "signal-media")]
impl From<signal_media::sanitize::Error> for SignalFfiError {
    fn from(e: signal_media::sanitize::Error) -> SignalFfiError {
        use signal_media::sanitize::Error;
        match e {
            Error::Io(e) => Self::Io(e.into()),
            Error::Parse(e) => Self::MediaSanitizeParse(e),
        }
    }
}

impl From<NullPointerError> for SignalFfiError {
    fn from(_: NullPointerError) -> SignalFfiError {
        SignalFfiError::NullPointer
    }
}

impl From<SignalFfiError> for IoError {
    fn from(e: SignalFfiError) -> Self {
        match e {
            SignalFfiError::Io(e) => e,
            e => IoError::new(IoErrorKind::Other, e.to_string()),
        }
    }
}

pub type SignalFfiResult<T> = Result<T, SignalFfiError>;

/// Represents an error returned by a callback, following the C conventions that 0 means "success".
#[derive(Debug)]
pub struct CallbackError {
    value: std::num::NonZeroI32,
}

impl CallbackError {
    /// Returns `None` if `value` is zero; otherwise, wraps the value in `Self`.
    pub fn check(value: i32) -> Option<Self> {
        let value = std::num::NonZeroI32::try_from(value).ok()?;
        Some(Self { value })
    }
}

impl fmt::Display for CallbackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "error code {}", self.value)
    }
}

impl std::error::Error for CallbackError {}
