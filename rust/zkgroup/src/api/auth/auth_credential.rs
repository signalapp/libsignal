//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::serialization::ReservedByte;
use crate::common::simple_types::*;
use crate::crypto;

#[derive(Copy, Clone, Serialize, Deserialize, PartialDefault)]
pub struct AuthCredential {
    pub(crate) reserved: ReservedByte,
    pub(crate) credential: crypto::credentials::AuthCredential,
    pub(crate) uid: crypto::uid_struct::UidStruct,
    pub(crate) redemption_time: CoarseRedemptionTime,
}

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct AuthCredentialResponse {
    pub(crate) reserved: ReservedByte,
    pub(crate) credential: crypto::credentials::AuthCredential,
    pub(crate) proof: crypto::proofs::AuthCredentialIssuanceProof,
}
