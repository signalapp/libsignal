//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use aes_gcm_siv::Error as AesGcmSivError;
use libsignal_protocol_rust::*;

#[derive(thiserror::Error, Debug)]
pub enum SignalFfiError {
    #[error(transparent)]
    Signal(#[from] SignalProtocolError),
    #[error("AES-GCM-SIV operation failed: {0}")]
    AesGcmSiv(#[from] AesGcmSivError),
    #[error("needed {0} elements only {1} provided")]
    InsufficientOutputSize(usize, usize),
    #[error("null pointer")]
    NullPointer,
    #[error("invalid UTF8 string")]
    InvalidUtf8String,
    // try to identify error or return unknown error
    #[error("{}", .0.downcast_ref::<&'static str>().map(|s| format!("unexpected panic: {}", s)).unwrap_or("unknown unexpected panic".to_owned()))]
    UnexpectedPanic(std::boxed::Box<dyn std::any::Any + std::marker::Send>),
    #[error("callback invocation returned error code {0}")]
    CallbackError(i32),
    #[error("invalid type")]
    InvalidType,
}
