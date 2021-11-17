//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct PniCredentialResponse {
    pub(crate) reserved: ReservedBytes,
    pub(crate) blinded_credential: crypto::credentials::BlindedPniCredential,
    pub(crate) proof: crypto::proofs::PniCredentialIssuanceProof,
}
