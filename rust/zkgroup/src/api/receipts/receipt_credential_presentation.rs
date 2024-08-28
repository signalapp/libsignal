//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::serialization::ReservedByte;
use crate::crypto::receipt_struct::ReceiptStruct;
use crate::{crypto, ReceiptLevel, ReceiptSerialBytes, Timestamp};

// Note that this type appears in gift badge messages, and thus in backups.
// Therefore it must be possible to at least deserialize any past versions of it,
// though they don't have to still be considered valid.
#[derive(Serialize, Deserialize, PartialDefault)]
pub struct ReceiptCredentialPresentation {
    pub(crate) reserved: ReservedByte,
    pub(crate) proof: crypto::proofs::ReceiptCredentialPresentationProof,
    pub(crate) receipt_expiration_time: Timestamp,
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

    pub fn get_receipt_expiration_time(&self) -> Timestamp {
        self.receipt_expiration_time
    }

    pub fn get_receipt_level(&self) -> ReceiptLevel {
        self.receipt_level
    }

    pub fn get_receipt_serial_bytes(&self) -> ReceiptSerialBytes {
        self.receipt_serial_bytes
    }
}
