//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::api;
use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuthCredentialPresentation {
    pub(crate) reserved: ReservedBytes,
    pub(crate) proof: crypto::proofs::AuthCredentialPresentationProof,
    pub(crate) ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) redemption_time: RedemptionTime,
}

impl AuthCredentialPresentation {
    pub fn get_uuid_ciphertext(&self) -> api::groups::UuidCiphertext {
        api::groups::UuidCiphertext {
            reserved: Default::default(),
            ciphertext: self.ciphertext,
        }
    }

    pub fn get_redemption_time(&self) -> RedemptionTime {
        self.redemption_time
    }
}
