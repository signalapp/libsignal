//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct ProfileKeyCommitment {
    pub(crate) reserved: ReservedBytes,
    pub(crate) commitment: crypto::profile_key_commitment::Commitment,
}
