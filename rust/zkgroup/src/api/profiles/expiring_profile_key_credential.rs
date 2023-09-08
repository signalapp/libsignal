//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ExpiringProfileKeyCredential {
    pub(crate) version: ReservedBytes,
    pub(crate) credential: crypto::credentials::ExpiringProfileKeyCredential,
    pub(crate) aci_bytes: UidBytes,
    pub(crate) profile_key_bytes: ProfileKeyBytes,
    pub(crate) credential_expiration_time: Timestamp,
}

impl ExpiringProfileKeyCredential {
    pub fn aci(&self) -> libsignal_protocol::Aci {
        uuid::Uuid::from_bytes(self.aci_bytes).into()
    }

    pub fn get_expiration_time(&self) -> Timestamp {
        self.credential_expiration_time
    }
}
