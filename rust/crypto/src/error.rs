//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[derive(displaydoc::Display, thiserror::Error, Debug)]
pub enum Error {
    /// "unknown {0} algorithm {1}"
    UnknownAlgorithm(&'static str, String),
    /// invalid key size
    InvalidKeySize,
    /// invalid nonce size
    InvalidNonceSize,
    /// invalid input size
    InvalidInputSize,
    /// invalid authentication tag
    InvalidTag,
    /// invalid object state
    InvalidState,
}

pub type Result<T> = std::result::Result<T, Error>;
