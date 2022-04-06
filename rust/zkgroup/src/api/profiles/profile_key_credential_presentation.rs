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

pub enum AnyProfileKeyCredentialPresentation {
    V1(ProfileKeyCredentialPresentationV1),
    V2(ProfileKeyCredentialPresentationV2),
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
            _ => Err(ZkGroupDeserializationFailure),
        }
    }

    pub fn get_uuid_ciphertext(&self) -> api::groups::UuidCiphertext {
        match self {
            AnyProfileKeyCredentialPresentation::V1(presentation_v1) => {
                presentation_v1.get_uuid_ciphertext()
            }
            AnyProfileKeyCredentialPresentation::V2(presentation_v2) => {
                presentation_v2.get_uuid_ciphertext()
            }
        }
    }

    pub fn get_profile_key_ciphertext(&self) -> api::groups::ProfileKeyCiphertext {
        match self {
            AnyProfileKeyCredentialPresentation::V1(presentation_v1) => {
                presentation_v1.get_profile_key_ciphertext()
            }
            AnyProfileKeyCredentialPresentation::V2(presentation_v2) => {
                presentation_v2.get_profile_key_ciphertext()
            }
        }
    }
}

impl Serialize for AnyProfileKeyCredentialPresentation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            AnyProfileKeyCredentialPresentation::V1(presentation_v1) => {
                presentation_v1.serialize(serializer)
            }
            AnyProfileKeyCredentialPresentation::V2(presentation_v2) => {
                presentation_v2.serialize(serializer)
            }
        }
    }
}
