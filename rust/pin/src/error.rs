//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/// Error types for pin operations
#[derive(displaydoc::Display, Debug, Clone, Eq, PartialEq)]
pub enum Error {
    /// Argon2 hashing error: {0}
    Argon2Error(argon2::Error),
    /// Error decoding a verification hash: {0}
    DecodingError(argon2::password_hash::errors::Error),
    /// Error looking up mrenclave
    MrenclaveLookupError,
}

impl From<argon2::Error> for Error {
    fn from(e: argon2::Error) -> Self {
        Error::Argon2Error(e)
    }
}

impl From<argon2::password_hash::errors::Error> for Error {
    fn from(e: argon2::password_hash::errors::Error) -> Self {
        Error::DecodingError(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
