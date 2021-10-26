//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct UuidCiphertext {
    pub(crate) reserved: ReservedBytes,
    pub(crate) ciphertext: crypto::uid_encryption::Ciphertext,
}
