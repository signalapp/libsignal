//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::crypto::receipt_struct::ReceiptStruct;
use crate::ReceiptExpirationTime;
use crate::ReceiptLevel;
use crate::ReceiptSerialBytes;
use crate::ReservedBytes;

#[derive(Serialize, Deserialize)]
pub struct ReceiptCredentialPresentation {
    pub(crate) reserved: ReservedBytes,
    pub(crate) proof: crypto::proofs::ReceiptCredentialPresentationProof,
    pub(crate) receipt_expiration_time: ReceiptExpirationTime,
    pub(crate) receipt_level: ReceiptLevel,
    pub(crate) receipt_serial_bytes: ReceiptSerialBytes,
}

impl ReceiptCredentialPresentation {
    pub fn get_receipt_struct(&self) -> ReceiptStruct {
        ReceiptStruct {
            receipt_serial_bytes: self.receipt_serial_bytes,
            receipt_expiration_time: self.receipt_expiration_time,
            receipt_level: self.receipt_level,
        }
    }

    pub fn get_receipt_expiration_time(&self) -> ReceiptExpirationTime {
        self.receipt_expiration_time
    }

    pub fn get_receipt_level(&self) -> ReceiptLevel {
        self.receipt_level
    }

    pub fn get_receipt_serial_bytes(&self) -> ReceiptSerialBytes {
        self.receipt_serial_bytes
    }
}
