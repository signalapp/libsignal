//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use aes_gcm_siv::Error as AesGcmSivError;
use libsignal_protocol_rust::*;

#[derive(thiserror::Error, Debug)]
pub enum SignalJniError {
    #[error(transparent)]
    Signal(#[from] SignalProtocolError),
    #[error(transparent)]
    AesGcmSiv(#[from] AesGcmSivError),
    #[error(transparent)]
    Jni(#[from] jni::errors::Error),
    #[error("bad parameter type {0}")]
    BadJniParameter(&'static str),
    #[error("calling {0} returned unexpected type {1}")]
    UnexpectedJniResultType(&'static str, &'static str),
    #[error("null handle")]
    NullHandle,
    #[error("integer overflow during conversion of {0}")]
    IntegerOverflow(String),
    #[error("{}", .0.downcast_ref::<&'static str>().map(|s| format!("unexpected panic: {}", s)).unwrap_or_else(|| "unknown unexpected panic".to_owned()))]
    UnexpectedPanic(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
    #[error("exception recieved during callback {0}")]
    ExceptionDuringCallback(String),
}

impl SignalJniError {
    pub fn to_signal_protocol_error(&self) -> SignalProtocolError {
        match self {
            SignalJniError::Signal(e) => e.clone(),
            SignalJniError::Jni(e) => SignalProtocolError::FfiBindingError(e.to_string()),
            SignalJniError::BadJniParameter(m) => {
                SignalProtocolError::InvalidArgument(m.to_string())
            }
            _ => SignalProtocolError::FfiBindingError(format!("{}", self)),
        }
    }
}

impl From<SignalJniError> for SignalProtocolError {
    fn from(err: SignalJniError) -> SignalProtocolError {
        match err {
            SignalJniError::Signal(e) => e,
            SignalJniError::Jni(e) => SignalProtocolError::FfiBindingError(e.to_string()),
            SignalJniError::BadJniParameter(m) => {
                SignalProtocolError::InvalidArgument(m.to_string())
            }
            _ => SignalProtocolError::FfiBindingError(format!("{}", err)),
        }
    }
}

#[cfg(test)]
mod formatting_tests {
    use super::SignalJniError::UnexpectedPanic;

    #[test]
    fn test_unexpected_panic_downcast() {
        let err = UnexpectedPanic(Box::new("error message"));
        
        assert_eq!(err.to_string(), "unexpected panic: error message")
    }

    #[test]
    fn test_unexpected_panic_no_downcast() {
        let err = UnexpectedPanic(Box::new(0));

        assert_eq!(err.to_string(), "unknown unexpected panic")
    }
}
