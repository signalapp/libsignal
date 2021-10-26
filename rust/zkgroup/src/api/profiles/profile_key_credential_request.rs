//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ProfileKeyCredentialRequest {
    pub(crate) reserved: ReservedBytes,
    pub(crate) public_key: crypto::profile_key_credential_request::PublicKey,
    pub(crate) ciphertext: crypto::profile_key_credential_request::Ciphertext,
    pub(crate) proof: crypto::proofs::ProfileKeyCredentialRequestProof,
}
