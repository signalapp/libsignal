//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use serde::{Deserialize, Serialize};

use crate::common::simple_types::*;
use crate::{api, crypto};

#[derive(Serialize, Deserialize)]
pub struct ReceiptCredentialRequestContext {
    pub(crate) reserved: ReservedBytes,
    pub(crate) receipt_serial_bytes: ReceiptSerialBytes,
    pub(crate) key_pair: crypto::receipt_credential_request::KeyPair,
    pub(crate) ciphertext_with_secret_nonce:
        crypto::receipt_credential_request::CiphertextWithSecretNonce,
}

impl ReceiptCredentialRequestContext {
    pub fn get_request(&self) -> api::receipts::ReceiptCredentialRequest {
        let ciphertext = self.ciphertext_with_secret_nonce.get_ciphertext();
        let public_key = self.key_pair.get_public_key();
        api::receipts::ReceiptCredentialRequest {
            reserved: Default::default(),
            public_key,
            ciphertext,
        }
    }
}
