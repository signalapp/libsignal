//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidKeySize,
    InvalidNonceSize,
    InvalidInputSize,
    InvalidOutputBuffer,
    InvalidTag,
    CpuidFailure,
}

pub type Result<T> = std::result::Result<T, Error>;
