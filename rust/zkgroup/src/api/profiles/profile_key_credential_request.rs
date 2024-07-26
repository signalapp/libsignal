//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::serialization::ReservedByte;
use crate::crypto;

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct ProfileKeyCredentialRequest {
    pub(crate) reserved: ReservedByte,
    pub(crate) public_key: crypto::profile_key_credential_request::PublicKey,
    pub(crate) ciphertext: crypto::profile_key_credential_request::Ciphertext,
    pub(crate) proof: crypto::proofs::ProfileKeyCredentialRequestProof,
}
