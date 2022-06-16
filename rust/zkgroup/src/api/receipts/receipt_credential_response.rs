//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use serde::{Deserialize, Serialize};

use crate::common::simple_types::*;
use crate::crypto;

#[derive(Serialize, Deserialize)]
pub struct ReceiptCredentialResponse {
    pub(crate) reserved: ReservedBytes,
    pub(crate) receipt_expiration_time: Timestamp,
    pub(crate) receipt_level: ReceiptLevel,
    pub(crate) blinded_credential: crypto::credentials::BlindedReceiptCredential,
    pub(crate) proof: crypto::proofs::ReceiptCredentialIssuanceProof,
}
