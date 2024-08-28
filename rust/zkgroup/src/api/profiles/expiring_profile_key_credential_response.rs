//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::serialization::ReservedByte;
use crate::common::simple_types::*;
use crate::crypto;

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct ExpiringProfileKeyCredentialResponse {
    pub(crate) reserved: ReservedByte,
    pub(crate) blinded_credential: crypto::credentials::BlindedExpiringProfileKeyCredential,
    pub(crate) credential_expiration_time: Timestamp,
    pub(crate) proof: crypto::proofs::ExpiringProfileKeyCredentialIssuanceProof,
}
