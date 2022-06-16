//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use serde::{Deserialize, Serialize};

use crate::common::simple_types::*;
use crate::crypto;

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct AuthCredential {
    pub(crate) reserved: ReservedBytes,
    pub(crate) credential: crypto::credentials::AuthCredential,
    pub(crate) uid: crypto::uid_struct::UidStruct,
    pub(crate) redemption_time: CoarseRedemptionTime,
}
