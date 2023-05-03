//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryFrom;
use std::fmt;

use attest::hsm_enclave::Error as HsmEnclaveError;
use attest::sgx_session::Error as SgxError;
use device_transfer::Error as DeviceTransferError;
use signal_grpc::Error as GrpcError;
use libsignal_protocol::*;
use signal_crypto::Error as SignalCryptoError;
use signal_pin::Error as PinError;
use usernames::UsernameError;
use zkgroup::{ZkGroupDeserializationFailure, ZkGroupVerificationFailure};

use crate::support::describe_panic;

use super::NullPointerError;

/// The top-level error type (opaquely) returned to C clients when something goes wrong.
#[derive(Debug)]
pub enum SignalFfiError {
    Signal(SignalProtocolError),
    DeviceTransfer(DeviceTransferError),
    Grpc(GrpcError),
    HsmEnclave(HsmEnclaveError),
    Sgx(SgxError),
    Pin(PinError),
    SignalCrypto(SignalCryptoError),
    ZkGroupVerificationFailure(ZkGroupVerificationFailure),
    ZkGroupDeserializationFailure(ZkGroupDeserializationFailure),
    UsernameError(UsernameError),
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
            SignalFfiError::Grpc(e) => {
                write!(f, "Grpc operation failed: {}", e)
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

impl From<GrpcError> for SignalFfiError {
    fn from(e: GrpcError) -> SignalFfiError {
        SignalFfiError::Grpc(e)
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

impl From<NullPointerError> for SignalFfiError {
    fn from(_: NullPointerError) -> SignalFfiError {
        SignalFfiError::NullPointer
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
