//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[derive(thiserror::Error, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    #[error("invalid AES-GCM-SIV key size")]
    InvalidKeySize,
    #[error("invalid AES-GCM-SIV nonce size")]
    InvalidNonceSize,
    #[error("invalid AES-GCM-SIV input size")]
    InvalidInputSize,
    #[error("invalid AES-GCM-SIV tag")]
    InvalidTag,
}

pub type Result<T> = std::result::Result<T, Error>;
