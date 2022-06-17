//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ExpiringProfileKeyCredentialResponse {
    pub(crate) version: ReservedBytes,
    pub(crate) blinded_credential: crypto::credentials::BlindedExpiringProfileKeyCredential,
    pub(crate) credential_expiration_time: Timestamp,
    pub(crate) proof: crypto::proofs::ExpiringProfileKeyCredentialIssuanceProof,
}
