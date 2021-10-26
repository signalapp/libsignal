//
// Copyright (C) 2020 Signal Messenger, LLC.
// All rights reserved.
//
// SPDX-License-Identifier: GPL-3.0-only
//

#![allow(non_snake_case)]

use crate::api;
use crate::common::simple_types::*;
use crate::crypto;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ProfileKeyCredentialPresentation {
    pub(crate) reserved: ReservedBytes,
    pub(crate) proof: crypto::proofs::ProfileKeyCredentialPresentationProof,
    pub(crate) uid_enc_ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) profile_key_enc_ciphertext: crypto::profile_key_encryption::Ciphertext,
}

impl ProfileKeyCredentialPresentation {
    pub fn get_uuid_ciphertext(&self) -> api::groups::UuidCiphertext {
        api::groups::UuidCiphertext {
            reserved: Default::default(),
            ciphertext: self.uid_enc_ciphertext,
        }
    }

    pub fn get_profile_key_ciphertext(&self) -> api::groups::ProfileKeyCiphertext {
        api::groups::ProfileKeyCiphertext {
            reserved: Default::default(),
            ciphertext: self.profile_key_enc_ciphertext,
        }
    }
}
