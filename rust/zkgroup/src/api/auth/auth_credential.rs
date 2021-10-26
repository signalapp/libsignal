//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use serde::{Deserialize, Serialize};

use crate::common::simple_types::*;
use crate::crypto;

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct AuthCredential {
    pub(crate) reserved: ReservedBytes,
    pub(crate) credential: crypto::credentials::AuthCredential,
    pub(crate) uid: crypto::uid_struct::UidStruct,
    pub(crate) redemption_time: RedemptionTime,
}
