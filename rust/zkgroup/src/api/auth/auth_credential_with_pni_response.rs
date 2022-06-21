//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuthCredentialWithPniResponse {
    pub(crate) reserved: ReservedBytes,
    pub(crate) credential: crypto::credentials::AuthCredentialWithPni,
    pub(crate) proof: crypto::proofs::AuthCredentialWithPniIssuanceProof,
}
