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

impl fmt::Display for SignalJniError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignalJniError::Signal(s) => write!(f, "{}", s),
            SignalJniError::AesGcmSiv(s) => write!(f, "{}", s),
            SignalJniError::Jni(s) => write!(f, "JNI error {}", s),
            SignalJniError::ExceptionDuringCallback(s) => {
                write!(f, "exception recieved during callback {}", s)
            }
            SignalJniError::NullHandle => write!(f, "null handle"),
            SignalJniError::BadJniParameter(m) => write!(f, "bad parameter type {}", m),
            SignalJniError::UnexpectedJniResultType(m, t) => {
                write!(f, "calling {} returned unexpected type {}", m, t)
            }
            SignalJniError::IntegerOverflow(m) => {
                write!(f, "integer overflow during conversion of {}", m)
            }
            SignalJniError::UnexpectedPanic(e) => match e.downcast_ref::<&'static str>() {
                Some(s) => write!(f, "unexpected panic: {}", s),
                None => write!(f, "unknown unexpected panic"),
            },
        }
    }
}

impl From<SignalProtocolError> for SignalJniError {
    fn from(e: SignalProtocolError) -> SignalJniError {
        SignalJniError::Signal(e)
    }
}

impl From<AesGcmSivError> for SignalJniError {
    fn from(e: AesGcmSivError) -> SignalJniError {
        SignalJniError::AesGcmSiv(e)
    }
}

impl From<jni::errors::Error> for SignalJniError {
    fn from(e: jni::errors::Error) -> SignalJniError {
        SignalJniError::Jni(e)
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
