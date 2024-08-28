//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::serialization::ReservedByte;
use crate::crypto;

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, Eq, PartialDefault)]
pub struct UuidCiphertext {
    pub(crate) reserved: ReservedByte,
    pub(crate) ciphertext: crypto::uid_encryption::Ciphertext,
}
