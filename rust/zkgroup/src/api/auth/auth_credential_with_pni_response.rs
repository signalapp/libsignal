//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::serialization::ReservedByte;
use crate::crypto;

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct AuthCredentialWithPniResponse {
    pub(crate) reserved: ReservedByte,
    pub(crate) credential: crypto::credentials::AuthCredentialWithPni,
    pub(crate) proof: crypto::proofs::AuthCredentialWithPniIssuanceProof,
}
