//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::simple_types::*;
use crate::{api, crypto};
use serde::{Deserialize, Serialize, Serializer};

#[derive(Serialize, Deserialize)]
pub struct PniCredentialPresentationV2 {
    pub(crate) version: ReservedBytes,
    pub(crate) proof: crypto::proofs::PniCredentialPresentationProofV2,
    pub(crate) aci_enc_ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) pni_enc_ciphertext: crypto::uid_encryption::Ciphertext,
    pub(crate) profile_key_enc_ciphertext: crypto::profile_key_encryption::Ciphertext,
}

impl PniCredentialPresentationV2 {
    pub fn get_aci_ciphertext(&self) -> api::groups::UuidCiphertext {
        api::groups::UuidCiphertext {
            reserved: Default::default(),
            ciphertext: self.aci_enc_ciphertext,
        }
    }

    pub fn get_pni_ciphertext(&self) -> api::groups::UuidCiphertext {
        api::groups::UuidCiphertext {
            reserved: Default::default(),
            ciphertext: self.pni_enc_ciphertext,
        }
    }

    pub fn get_profile_key_ciphertext(&self) -> api::groups::ProfileKeyCiphertext {
        api::groups::ProfileKeyCiphertext {
            reserved: Default::default(),
            ciphertext: self.profile_key_enc_ciphertext,
        }
    }
}

pub enum AnyPniCredentialPresentation {
    V2(PniCredentialPresentationV2),
}

impl AnyPniCredentialPresentation {
    pub fn new(presentation_bytes: &[u8]) -> Result<Self, ZkGroupDeserializationFailure> {
        match presentation_bytes[0] {
            PRESENTATION_VERSION_1 => {
                // No longer supported.
                Err(ZkGroupDeserializationFailure)
            }
            PRESENTATION_VERSION_2 => {
                match bincode::deserialize::<PniCredentialPresentationV2>(presentation_bytes) {
                    Ok(presentation) => Ok(AnyPniCredentialPresentation::V2(presentation)),
                    Err(_) => Err(ZkGroupDeserializationFailure),
                }
            }
            _ => Err(ZkGroupDeserializationFailure),
        }
    }

    pub fn get_aci_ciphertext(&self) -> api::groups::UuidCiphertext {
        match self {
            AnyPniCredentialPresentation::V2(presentation_v2) => {
                presentation_v2.get_aci_ciphertext()
            }
        }
    }

    pub fn get_pni_ciphertext(&self) -> api::groups::UuidCiphertext {
        match self {
            AnyPniCredentialPresentation::V2(presentation_v2) => {
                presentation_v2.get_pni_ciphertext()
            }
        }
    }

    pub fn get_profile_key_ciphertext(&self) -> api::groups::ProfileKeyCiphertext {
        match self {
            AnyPniCredentialPresentation::V2(presentation_v2) => {
                presentation_v2.get_profile_key_ciphertext()
            }
        }
    }
}

impl Serialize for AnyPniCredentialPresentation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            AnyPniCredentialPresentation::V2(presentation_v2) => {
                presentation_v2.serialize(serializer)
            }
        }
    }
}
