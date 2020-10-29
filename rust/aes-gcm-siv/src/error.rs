//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
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
