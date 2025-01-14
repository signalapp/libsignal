//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

/// Error types for pin operations
#[derive(displaydoc::Display, thiserror::Error, Debug, Clone, Eq, PartialEq, derive_more::From)]
pub enum Error {
    /// Argon2 hashing error: {0}
    Argon2Error(argon2::Error),
    /// Error decoding a verification hash: {0}
    DecodingError(argon2::password_hash::errors::Error),
    /// Error looking up mrenclave
    MrenclaveLookupError,
}

pub type Result<T> = std::result::Result<T, Error>;
