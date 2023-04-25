//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use serde::{Deserialize, Serialize};

use crate::{RandomnessBytes, ReservedBytes};

#[derive(Serialize, Deserialize)]
pub struct GenericServerSecretParams {
    reserved: ReservedBytes,
    pub(crate) credential_key: zkcredential::credentials::CredentialKeyPair,
}

impl GenericServerSecretParams {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        Self {
            reserved: [0],
            credential_key: zkcredential::credentials::CredentialKeyPair::generate(randomness),
        }
    }

    pub fn get_public_params(&self) -> GenericServerPublicParams {
        GenericServerPublicParams {
            reserved: [0],
            credential_key: self.credential_key.public_key().clone(),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct GenericServerPublicParams {
    reserved: ReservedBytes,
    pub(crate) credential_key: zkcredential::credentials::CredentialPublicKey,
}
