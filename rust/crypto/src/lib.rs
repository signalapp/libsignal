//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod error;
mod hash;

pub use {
    error::{Error, Result},
    hash::{CryptographicHash, CryptographicMac},
};
