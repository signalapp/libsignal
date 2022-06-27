//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::simple_types::*;
use crate::{api, crypto};
use serde::{Deserialize, Serialize, Serializer};

#[derive(Serialize, Deserialize)]
pub struct ProfileKeyCredentialPresentationV1 {
    pub(crate) reserved: ReservedBytes,
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
#[derive(Serialize, Deserialize)]
pub struct ProfileKeyCredentialPresentationV2 {
    pub(crate) version: ReservedBytes,
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

#[derive(Serialize, Deserialize)]
pub struct ExpiringProfileKeyCredentialPresentation {
    pub(crate) version: ReservedBytes,
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

pub enum AnyProfileKeyCredentialPresentation {
    V1(ProfileKeyCredentialPresentationV1),
    V2(ProfileKeyCredentialPresentationV2),
    V3(ExpiringProfileKeyCredentialPresentation),
}

impl AnyProfileKeyCredentialPresentation {
    pub fn new(presentation_bytes: &[u8]) -> Result<Self, ZkGroupDeserializationFailure> {
        match presentation_bytes[0] {
            PRESENTATION_VERSION_1 => {
                match bincode::deserialize::<ProfileKeyCredentialPresentationV1>(presentation_bytes)
                {
                    Ok(presentation) => Ok(AnyProfileKeyCredentialPresentation::V1(presentation)),
                    Err(_) => Err(ZkGroupDeserializationFailure),
                }
            }
            PRESENTATION_VERSION_2 => {
                match bincode::deserialize::<ProfileKeyCredentialPresentationV2>(presentation_bytes)
                {
                    Ok(presentation) => Ok(AnyProfileKeyCredentialPresentation::V2(presentation)),
                    Err(_) => Err(ZkGroupDeserializationFailure),
                }
            }
            PRESENTATION_VERSION_3 => {
                match bincode::deserialize::<ExpiringProfileKeyCredentialPresentation>(
                    presentation_bytes,
                ) {
                    Ok(presentation) => Ok(AnyProfileKeyCredentialPresentation::V3(presentation)),
                    Err(_) => Err(ZkGroupDeserializationFailure),
                }
            }
            _ => Err(ZkGroupDeserializationFailure),
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
            reserved: [PRESENTATION_VERSION_1],
            proof: crypto::proofs::ProfileKeyCredentialPresentationProofV1::from_invalid_proof(
                // Hardcoded length of a valid v1 proof.
                vec![0; 0x0140],
            ),
            uid_enc_ciphertext: self.get_uuid_ciphertext().ciphertext,
            profile_key_enc_ciphertext: self.get_profile_key_ciphertext().ciphertext,
        };
        let result = bincode::serialize(&v1).expect("can serialize");
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

impl From<ProfileKeyCredentialPresentationV1> for AnyProfileKeyCredentialPresentation {
    fn from(presentation: ProfileKeyCredentialPresentationV1) -> Self {
        Self::V1(presentation)
    }
}
impl From<ProfileKeyCredentialPresentationV2> for AnyProfileKeyCredentialPresentation {
    fn from(presentation: ProfileKeyCredentialPresentationV2) -> Self {
        Self::V2(presentation)
    }
}
impl From<ExpiringProfileKeyCredentialPresentation> for AnyProfileKeyCredentialPresentation {
    fn from(presentation: ExpiringProfileKeyCredentialPresentation) -> Self {
        Self::V3(presentation)
    }
}
