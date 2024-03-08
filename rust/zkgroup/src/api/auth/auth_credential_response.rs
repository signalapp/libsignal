//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::serialization::ReservedByte;
use crate::crypto;

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct AuthCredentialResponse {
    pub(crate) reserved: ReservedByte,
    pub(crate) credential: crypto::credentials::AuthCredential,
    pub(crate) proof: crypto::proofs::AuthCredentialIssuanceProof,
}
