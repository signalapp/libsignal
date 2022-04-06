//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::api;
use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::simple_types::*;
use crate::crypto;
use serde::Serializer;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AuthCredentialPresentationV1 {
    pub(crate) reserved: ReservedBytes,
    pub(crate) proof: crypto::proofs::AuthCredentialPresentationProofV1,
    pub(crate) ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) redemption_time: RedemptionTime,
}

impl AuthCredentialPresentationV1 {
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

#[derive(Serialize, Deserialize)]
pub struct AuthCredentialPresentationV2 {
    pub(crate) version: ReservedBytes,
    pub(crate) proof: crypto::proofs::AuthCredentialPresentationProofV2,
    pub(crate) ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) redemption_time: RedemptionTime,
}

impl AuthCredentialPresentationV2 {
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

pub enum AnyAuthCredentialPresentation {
    V1(AuthCredentialPresentationV1),
    V2(AuthCredentialPresentationV2),
}

impl AnyAuthCredentialPresentation {
    pub fn new(presentation_bytes: &[u8]) -> Result<Self, ZkGroupDeserializationFailure> {
        match presentation_bytes[0] {
            PRESENTATION_VERSION_1 => {
                match bincode::deserialize::<AuthCredentialPresentationV1>(presentation_bytes) {
                    Ok(presentation) => Ok(AnyAuthCredentialPresentation::V1(presentation)),
                    Err(_) => Err(ZkGroupDeserializationFailure),
                }
            }
            PRESENTATION_VERSION_2 => {
                match bincode::deserialize::<AuthCredentialPresentationV2>(presentation_bytes) {
                    Ok(presentation) => Ok(AnyAuthCredentialPresentation::V2(presentation)),
                    Err(_) => Err(ZkGroupDeserializationFailure),
                }
            }
            _ => Err(ZkGroupDeserializationFailure),
        }
    }

    pub fn get_uuid_ciphertext(&self) -> api::groups::UuidCiphertext {
        match self {
            AnyAuthCredentialPresentation::V1(presentation_v1) => {
                presentation_v1.get_uuid_ciphertext()
            }
            AnyAuthCredentialPresentation::V2(presentation_v2) => {
                presentation_v2.get_uuid_ciphertext()
            }
        }
    }

    pub fn get_redemption_time(&self) -> RedemptionTime {
        match self {
            AnyAuthCredentialPresentation::V1(presentation_v1) => {
                presentation_v1.get_redemption_time()
            }
            AnyAuthCredentialPresentation::V2(presentation_v2) => {
                presentation_v2.get_redemption_time()
            }
        }
    }
}

impl Serialize for AnyAuthCredentialPresentation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            AnyAuthCredentialPresentation::V1(presentation_v1) => {
                presentation_v1.serialize(serializer)
            }
            AnyAuthCredentialPresentation::V2(presentation_v2) => {
                presentation_v2.serialize(serializer)
            }
        }
    }
}
