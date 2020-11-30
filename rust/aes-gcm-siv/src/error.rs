//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidKeySize,
    InvalidNonceSize,
    InvalidInputSize,
    InvalidTag,
}

pub type Result<T> = std::result::Result<T, Error>;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let err_msg = match self {
            Error::InvalidKeySize => "invalid AES-GCM-SIV key size",
            Error::InvalidNonceSize => "invalid AES-GCM-SIV nonce size",
            Error::InvalidInputSize => "invalid AES-GCM-SIV input size",
            Error::InvalidTag => "invalid AES-GCM-SIV tag",
        };

        write!(f, "{}", err_msg)
    }
}
