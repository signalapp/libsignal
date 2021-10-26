//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ProfileKeyCredentialResponse {
    pub(crate) reserved: ReservedBytes,
    pub(crate) blinded_credential: crypto::credentials::BlindedProfileKeyCredential,
    pub(crate) proof: crypto::proofs::ProfileKeyCredentialIssuanceProof,
}
