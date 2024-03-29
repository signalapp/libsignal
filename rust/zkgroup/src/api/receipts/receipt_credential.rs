//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::serialization::ReservedByte;
use crate::common::simple_types::*;
use crate::crypto;

#[derive(Copy, Clone, Serialize, Deserialize, PartialDefault)]
pub struct ReceiptCredential {
    pub(crate) reserved: ReservedByte,
    pub(crate) credential: crypto::credentials::ReceiptCredential,
    pub(crate) receipt_expiration_time: Timestamp,
    pub(crate) receipt_level: ReceiptLevel,
    pub(crate) receipt_serial_bytes: ReceiptSerialBytes,
}

impl ReceiptCredential {
    pub fn get_receipt_expiration_time(&self) -> Timestamp {
        self.receipt_expiration_time
    }

    pub fn get_receipt_level(&self) -> ReceiptLevel {
        self.receipt_level
    }
}
