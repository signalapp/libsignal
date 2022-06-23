//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct UuidCiphertext {
    pub(crate) reserved: ReservedBytes,
    pub(crate) ciphertext: crypto::uid_encryption::Ciphertext,
}
