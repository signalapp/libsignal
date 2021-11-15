//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct PniCredential {
    pub(crate) reserved: ReservedBytes,
    pub(crate) credential: crypto::credentials::PniCredential,
    pub(crate) aci_bytes: UidBytes,
    pub(crate) pni_bytes: UidBytes,
    pub(crate) profile_key_bytes: ProfileKeyBytes,
}
