//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Error {
    UnknownAlgorithm(&'static str, String),
    InvalidKeySize,
    InvalidNonceSize,
    InvalidInputSize,
    InvalidTag,
    InvalidState,
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::UnknownAlgorithm(typ, named) => write!(f, "unknown {} algorithm {}", typ, named),
            Error::InvalidKeySize => write!(f, "invalid key size"),
            Error::InvalidNonceSize => write!(f, "invalid nonce size"),
            Error::InvalidInputSize => write!(f, "invalid input size"),
            Error::InvalidTag => write!(f, "invalid authentication tag"),
            Error::InvalidState => write!(f, "invalid object state"),
        }
    }
}
