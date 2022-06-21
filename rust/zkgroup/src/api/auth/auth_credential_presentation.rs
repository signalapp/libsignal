//
// Copyright 2020-2022 Signal Messenger, LLC.
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
    pub(crate) redemption_time: CoarseRedemptionTime,
}

impl AuthCredentialPresentationV1 {
    pub fn get_uuid_ciphertext(&self) -> api::groups::UuidCiphertext {
        api::groups::UuidCiphertext {
            reserved: Default::default(),
            ciphertext: self.ciphertext,
        }
    }

    pub fn get_redemption_time(&self) -> CoarseRedemptionTime {
        self.redemption_time
    }
}

/// Like [`AuthCredentialPresentationV1`], but with an optimized proof.
#[derive(Serialize, Deserialize)]
pub struct AuthCredentialPresentationV2 {
    pub(crate) version: ReservedBytes,
    pub(crate) proof: crypto::proofs::AuthCredentialPresentationProofV2,
    pub(crate) ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) redemption_time: CoarseRedemptionTime,
}

impl AuthCredentialPresentationV2 {
    pub fn get_uuid_ciphertext(&self) -> api::groups::UuidCiphertext {
        api::groups::UuidCiphertext {
            reserved: Default::default(),
            ciphertext: self.ciphertext,
        }
    }

    pub fn get_redemption_time(&self) -> CoarseRedemptionTime {
        self.redemption_time
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthCredentialWithPniPresentation {
    pub(crate) version: ReservedBytes,
    pub(crate) proof: crypto::proofs::AuthCredentialWithPniPresentationProof,
    pub(crate) aci_ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) pni_ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) redemption_time: Timestamp,
}

impl AuthCredentialWithPniPresentation {
    pub fn get_aci_ciphertext(&self) -> api::groups::UuidCiphertext {
        api::groups::UuidCiphertext {
            reserved: Default::default(),
            ciphertext: self.aci_ciphertext,
        }
    }

    pub fn get_pni_ciphertext(&self) -> api::groups::UuidCiphertext {
        api::groups::UuidCiphertext {
            reserved: Default::default(),
            ciphertext: self.pni_ciphertext,
        }
    }

    pub fn get_redemption_time(&self) -> Timestamp {
        self.redemption_time
    }
}

#[allow(clippy::large_enum_variant)]
pub enum AnyAuthCredentialPresentation {
    V1(AuthCredentialPresentationV1),
    V2(AuthCredentialPresentationV2),
    V3(AuthCredentialWithPniPresentation),
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
            PRESENTATION_VERSION_3 => {
                match bincode::deserialize::<AuthCredentialWithPniPresentation>(presentation_bytes)
                {
                    Ok(presentation) => Ok(AnyAuthCredentialPresentation::V3(presentation)),
                    Err(_) => Err(ZkGroupDeserializationFailure),
                }
            }
            _ => Err(ZkGroupDeserializationFailure),
        }
    }

    pub fn get_uuid_ciphertext(&self) -> api::groups::UuidCiphertext {
        match self {
            AnyAuthCredentialPresentation::V1(presentation) => presentation.get_uuid_ciphertext(),
            AnyAuthCredentialPresentation::V2(presentation) => presentation.get_uuid_ciphertext(),
            AnyAuthCredentialPresentation::V3(presentation) => presentation.get_aci_ciphertext(),
        }
    }

    pub fn get_pni_ciphertext(&self) -> Option<api::groups::UuidCiphertext> {
        match self {
            AnyAuthCredentialPresentation::V1(_presentation) => None,
            AnyAuthCredentialPresentation::V2(_presentation) => None,
            AnyAuthCredentialPresentation::V3(presentation) => {
                Some(presentation.get_pni_ciphertext())
            }
        }
    }

    pub fn get_redemption_time(&self) -> Timestamp {
        match self {
            AnyAuthCredentialPresentation::V1(presentation) => {
                u64::from(presentation.get_redemption_time()) * SECONDS_PER_DAY
            }
            AnyAuthCredentialPresentation::V2(presentation) => {
                u64::from(presentation.get_redemption_time()) * SECONDS_PER_DAY
            }
            AnyAuthCredentialPresentation::V3(presentation) => presentation.get_redemption_time(),
        }
    }
}

impl Serialize for AnyAuthCredentialPresentation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            AnyAuthCredentialPresentation::V1(presentation) => presentation.serialize(serializer),
            AnyAuthCredentialPresentation::V2(presentation) => presentation.serialize(serializer),
            AnyAuthCredentialPresentation::V3(presentation) => presentation.serialize(serializer),
        }
    }
}

impl From<AuthCredentialPresentationV1> for AnyAuthCredentialPresentation {
    fn from(presentation: AuthCredentialPresentationV1) -> Self {
        Self::V1(presentation)
    }
}
impl From<AuthCredentialPresentationV2> for AnyAuthCredentialPresentation {
    fn from(presentation: AuthCredentialPresentationV2) -> Self {
        Self::V2(presentation)
    }
}
impl From<AuthCredentialWithPniPresentation> for AnyAuthCredentialPresentation {
    fn from(presentation: AuthCredentialWithPniPresentation) -> Self {
        Self::V3(presentation)
    }
}
