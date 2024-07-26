//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::serialization::ReservedByte;
use crate::RandomnessBytes;

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct GenericServerSecretParams {
    version: ReservedByte,
    pub(crate) credential_key: zkcredential::credentials::CredentialKeyPair,
}

impl GenericServerSecretParams {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        Self {
            version: Default::default(),
            credential_key: zkcredential::credentials::CredentialKeyPair::generate(randomness),
        }
    }

    pub fn get_public_params(&self) -> GenericServerPublicParams {
        GenericServerPublicParams {
            version: self.version,
            credential_key: self.credential_key.public_key().clone(),
        }
    }
}

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct GenericServerPublicParams {
    version: ReservedByte,
    pub(crate) credential_key: zkcredential::credentials::CredentialPublicKey,
}
