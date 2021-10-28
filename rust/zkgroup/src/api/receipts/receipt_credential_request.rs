//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use serde::{Deserialize, Serialize};

use crate::common::simple_types::*;
use crate::crypto;

#[derive(Serialize, Deserialize)]
pub struct ReceiptCredentialRequest {
    pub(crate) reserved: ReservedBytes,
    pub(crate) public_key: crypto::receipt_credential_request::PublicKey,
    pub(crate) ciphertext: crypto::receipt_credential_request::Ciphertext,
}
