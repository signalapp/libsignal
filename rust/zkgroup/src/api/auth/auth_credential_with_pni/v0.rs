//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::api::auth::auth_credential_with_pni::AuthCredentialWithPniVersion;
use crate::common::serialization::VersionByte;
use crate::common::simple_types::*;
use crate::crypto;

#[derive(Copy, Clone, Serialize, Deserialize, PartialDefault)]
pub struct AuthCredentialWithPniV0 {
    pub(crate) version: VersionByte<{ AuthCredentialWithPniVersion::V0 as u8 }>,
    pub(crate) credential: crypto::credentials::AuthCredentialWithPni,
    pub(crate) aci: crypto::uid_struct::UidStruct,
    pub(crate) pni: crypto::uid_struct::UidStruct,
    pub(crate) redemption_time: Timestamp,
}

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct AuthCredentialWithPniV0Response {
    pub(crate) version: VersionByte<{ AuthCredentialWithPniVersion::V0 as u8 }>,
    pub(crate) credential: crypto::credentials::AuthCredentialWithPni,
    pub(crate) proof: crypto::proofs::AuthCredentialWithPniIssuanceProof,
}
