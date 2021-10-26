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

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ReceiptCredential {
    pub(crate) reserved: ReservedBytes,
    pub(crate) credential: crypto::credentials::ReceiptCredential,
    pub(crate) receipt_expiration_time: ReceiptExpirationTime,
    pub(crate) receipt_level: ReceiptLevel,
    pub(crate) receipt_serial_bytes: ReceiptSerialBytes,
}

impl ReceiptCredential {
    pub fn get_receipt_expiration_time(&self) -> ReceiptExpirationTime {
        self.receipt_expiration_time
    }

    pub fn get_receipt_level(&self) -> ReceiptLevel {
        self.receipt_level
    }
}
