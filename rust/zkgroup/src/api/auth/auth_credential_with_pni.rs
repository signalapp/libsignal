//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::simple_types::*;
use crate::crypto;

#[derive(Copy, Clone, Serialize, Deserialize, PartialDefault)]
pub struct AuthCredentialWithPni {
    pub(crate) reserved: ReservedBytes,
    pub(crate) credential: crypto::credentials::AuthCredentialWithPni,
    pub(crate) aci: crypto::uid_struct::UidStruct,
    pub(crate) pni: crypto::uid_struct::UidStruct,
    pub(crate) redemption_time: Timestamp,
}
