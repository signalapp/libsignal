//
// Copyright (C) 2021 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};

use crate::common::simple_types::*;
use crate::crypto;

#[derive(Serialize, Deserialize)]
pub struct ReceiptCredentialRequest {
    pub(crate) reserved: ReservedBytes,
    pub(crate) public_key: crypto::receipt_credential_request::PublicKey,
    pub(crate) ciphertext: crypto::receipt_credential_request::Ciphertext,
}
