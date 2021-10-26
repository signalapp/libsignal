//
// Copyright (C) 2021 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};

use crate::api;
use crate::common::simple_types::*;
use crate::crypto;

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
