//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::serialization::ReservedByte;
use crate::common::simple_types::*;
use crate::crypto;

#[derive(Copy, Clone, Serialize, Deserialize, PartialDefault)]
pub struct ExpiringProfileKeyCredential {
    pub(crate) reserved: ReservedByte,
    pub(crate) credential: crypto::credentials::ExpiringProfileKeyCredential,
    pub(crate) aci_bytes: UidBytes,
    pub(crate) profile_key_bytes: ProfileKeyBytes,
    pub(crate) credential_expiration_time: Timestamp,
}

impl ExpiringProfileKeyCredential {
    pub fn aci(&self) -> libsignal_core::Aci {
        uuid::Uuid::from_bytes(self.aci_bytes).into()
    }

    pub fn get_expiration_time(&self) -> Timestamp {
        self.credential_expiration_time
    }
}
