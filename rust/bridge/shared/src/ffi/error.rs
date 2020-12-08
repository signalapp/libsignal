//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;

use aes_gcm_siv::Error as AesGcmSivError;
use libsignal_protocol_rust::*;

#[derive(Debug)]
pub enum SignalFfiError {
    Signal(SignalProtocolError),
    AesGcmSiv(AesGcmSivError),
    InsufficientOutputSize(usize, usize),
    NullPointer,
    InvalidUtf8String,
    UnexpectedPanic(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
    InvalidType,
}

impl fmt::Display for SignalFfiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SignalFfiError::Signal(s) => write!(f, "{}", s),
            SignalFfiError::AesGcmSiv(c) => {
                write!(f, "AES-GCM-SIV operation failed: {}", c)
            }
            SignalFfiError::NullPointer => write!(f, "null pointer"),
            SignalFfiError::InvalidType => write!(f, "invalid type"),
            SignalFfiError::InvalidUtf8String => write!(f, "invalid UTF8 string"),
            SignalFfiError::InsufficientOutputSize(n, h) => {
                write!(f, "needed {} elements only {} provided", n, h)
            }

            SignalFfiError::UnexpectedPanic(e) => match e.downcast_ref::<&'static str>() {
                Some(s) => write!(f, "unexpected panic: {}", s),
                None => write!(f, "unknown unexpected panic"),
            },
        }
    }
}

impl From<SignalProtocolError> for SignalFfiError {
    fn from(e: SignalProtocolError) -> SignalFfiError {
        SignalFfiError::Signal(e)
    }
}

impl From<AesGcmSivError> for SignalFfiError {
    fn from(e: AesGcmSivError) -> SignalFfiError {
        SignalFfiError::AesGcmSiv(e)
    }
}
