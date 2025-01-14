//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize, Serializer};

use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::serialization::VersionByte;
use crate::common::simple_types::*;
use crate::{api, crypto};

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct ProfileKeyCredentialPresentationV1 {
    pub(crate) version: u8, // Not ReservedByte or VersionByte to allow deserializing a V2 presentation as V1.
    pub(crate) proof: crypto::proofs::ProfileKeyCredentialPresentationProofV1,
    pub(crate) uid_enc_ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) profile_key_enc_ciphertext: crypto::profile_key_encryption::Ciphertext,
}

impl ProfileKeyCredentialPresentationV1 {
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

/// Like [`ProfileKeyCredentialPresentationV1`], but with an optimized proof.
#[derive(Serialize, Deserialize, PartialDefault)]
pub struct ProfileKeyCredentialPresentationV2 {
    pub(crate) version: VersionByte<PRESENTATION_VERSION_2>,
    pub(crate) proof: crypto::proofs::ProfileKeyCredentialPresentationProofV2,
    pub(crate) uid_enc_ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) profile_key_enc_ciphertext: crypto::profile_key_encryption::Ciphertext,
}

impl ProfileKeyCredentialPresentationV2 {
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

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct ExpiringProfileKeyCredentialPresentation {
    pub(crate) version: VersionByte<PRESENTATION_VERSION_3>,
    pub(crate) proof: crypto::proofs::ExpiringProfileKeyCredentialPresentationProof,
    pub(crate) uid_enc_ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) profile_key_enc_ciphertext: crypto::profile_key_encryption::Ciphertext,
    pub(crate) credential_expiration_time: Timestamp,
}

impl ExpiringProfileKeyCredentialPresentation {
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

    pub fn get_expiration_time(&self) -> Timestamp {
        self.credential_expiration_time
    }
}

#[derive(derive_more::From)]
pub enum AnyProfileKeyCredentialPresentation {
    V1(ProfileKeyCredentialPresentationV1),
    V2(ProfileKeyCredentialPresentationV2),
    V3(ExpiringProfileKeyCredentialPresentation),
}

impl AnyProfileKeyCredentialPresentation {
    pub fn new(presentation_bytes: &[u8]) -> Result<Self, ZkGroupDeserializationFailure> {
        match presentation_bytes[0] {
            PRESENTATION_VERSION_1 => {
                crate::deserialize::<ProfileKeyCredentialPresentationV1>(presentation_bytes)
                    .map(AnyProfileKeyCredentialPresentation::V1)
            }
            PRESENTATION_VERSION_2 => {
                crate::deserialize::<ProfileKeyCredentialPresentationV2>(presentation_bytes)
                    .map(AnyProfileKeyCredentialPresentation::V2)
            }
            PRESENTATION_VERSION_3 => {
                crate::deserialize::<ExpiringProfileKeyCredentialPresentation>(presentation_bytes)
                    .map(AnyProfileKeyCredentialPresentation::V3)
            }
            _ => Err(ZkGroupDeserializationFailure::new::<Self>()),
        }
    }

    pub fn get_uuid_ciphertext(&self) -> api::groups::UuidCiphertext {
        match self {
            AnyProfileKeyCredentialPresentation::V1(presentation) => {
                presentation.get_uuid_ciphertext()
            }
            AnyProfileKeyCredentialPresentation::V2(presentation) => {
                presentation.get_uuid_ciphertext()
            }
            AnyProfileKeyCredentialPresentation::V3(presentation) => {
                presentation.get_uuid_ciphertext()
            }
        }
    }

    pub fn get_profile_key_ciphertext(&self) -> api::groups::ProfileKeyCiphertext {
        match self {
            AnyProfileKeyCredentialPresentation::V1(presentation) => {
                presentation.get_profile_key_ciphertext()
            }
            AnyProfileKeyCredentialPresentation::V2(presentation) => {
                presentation.get_profile_key_ciphertext()
            }
            AnyProfileKeyCredentialPresentation::V3(presentation) => {
                presentation.get_profile_key_ciphertext()
            }
        }
    }

    pub fn to_structurally_valid_v1_presentation_bytes(&self) -> Vec<u8> {
        let v1 = ProfileKeyCredentialPresentationV1 {
            version: PRESENTATION_VERSION_1,
            proof: crypto::proofs::ProfileKeyCredentialPresentationProofV1::from_invalid_proof(
                // Hardcoded length of a valid v1 proof.
                vec![0; 0x0140],
            ),
            uid_enc_ciphertext: self.get_uuid_ciphertext().ciphertext,
            profile_key_enc_ciphertext: self.get_profile_key_ciphertext().ciphertext,
        };
        let result = crate::serialize(&v1);
        debug_assert_eq!(result.len(), PROFILE_KEY_CREDENTIAL_PRESENTATION_V1_LEN);
        result
    }
}

impl Serialize for AnyProfileKeyCredentialPresentation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            AnyProfileKeyCredentialPresentation::V1(presentation) => {
                presentation.serialize(serializer)
            }
            AnyProfileKeyCredentialPresentation::V2(presentation) => {
                presentation.serialize(serializer)
            }
            AnyProfileKeyCredentialPresentation::V3(presentation) => {
                presentation.serialize(serializer)
            }
        }
    }
}
