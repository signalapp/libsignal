//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use partial_default::PartialDefault;
use serde::{Deserialize, Serialize, Serializer};

use crate::auth::AuthCredentialWithPniZkcPresentation;
use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::serialization::VersionByte;
use crate::common::simple_types::*;
use crate::{api, crypto};

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct AuthCredentialPresentationV2 {
    pub(crate) version: VersionByte<PRESENTATION_VERSION_2>,
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

#[derive(Serialize, Deserialize, PartialDefault)]
pub struct AuthCredentialWithPniPresentation {
    pub(crate) version: VersionByte<PRESENTATION_VERSION_3>,
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
    V2(AuthCredentialPresentationV2),
    V3(AuthCredentialWithPniPresentation),
    V4(AuthCredentialWithPniZkcPresentation),
}

#[repr(u8)]
#[derive(
    Copy, Clone, Debug, PartialDefault, num_enum::IntoPrimitive, num_enum::TryFromPrimitive,
)]
enum PresentationVersion {
    // V1 is no longer supported.
    #[partial_default]
    V2 = PRESENTATION_VERSION_2,
    V3 = PRESENTATION_VERSION_3,
    V4 = PRESENTATION_VERSION_4,
}

impl AnyAuthCredentialPresentation {
    pub fn new(presentation_bytes: &[u8]) -> Result<Self, ZkGroupDeserializationFailure> {
        let first = *presentation_bytes
            .first()
            .ok_or(ZkGroupDeserializationFailure)?;
        let version =
            PresentationVersion::try_from(first).map_err(|_| ZkGroupDeserializationFailure)?;
        match version {
            PresentationVersion::V2 => {
                Ok(crate::deserialize::<AuthCredentialPresentationV2>(presentation_bytes)?.into())
            }
            PresentationVersion::V3 => Ok(crate::deserialize::<AuthCredentialWithPniPresentation>(
                presentation_bytes,
            )?
            .into()),
            PresentationVersion::V4 => Ok(crate::deserialize::<
                AuthCredentialWithPniZkcPresentation,
            >(presentation_bytes)?
            .into()),
        }
    }

    pub fn get_uuid_ciphertext(&self) -> api::groups::UuidCiphertext {
        match self {
            AnyAuthCredentialPresentation::V2(presentation) => presentation.get_uuid_ciphertext(),
            AnyAuthCredentialPresentation::V3(presentation) => presentation.get_aci_ciphertext(),
            AnyAuthCredentialPresentation::V4(presentation) => presentation.aci_ciphertext(),
        }
    }

    pub fn get_pni_ciphertext(&self) -> Option<api::groups::UuidCiphertext> {
        match self {
            AnyAuthCredentialPresentation::V2(_presentation) => None,
            AnyAuthCredentialPresentation::V3(presentation) => {
                Some(presentation.get_pni_ciphertext())
            }
            AnyAuthCredentialPresentation::V4(presentation) => Some(presentation.pni_ciphertext()),
        }
    }

    pub fn get_redemption_time(&self) -> Timestamp {
        match self {
            AnyAuthCredentialPresentation::V2(presentation) => {
                u64::from(presentation.get_redemption_time()) * SECONDS_PER_DAY
            }
            AnyAuthCredentialPresentation::V3(presentation) => presentation.get_redemption_time(),
            AnyAuthCredentialPresentation::V4(presentation) => presentation.redemption_time(),
        }
    }
}

impl Serialize for AnyAuthCredentialPresentation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            AnyAuthCredentialPresentation::V2(presentation) => presentation.serialize(serializer),
            AnyAuthCredentialPresentation::V3(presentation) => presentation.serialize(serializer),
            AnyAuthCredentialPresentation::V4(presentation) => presentation.serialize(serializer),
        }
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
impl From<AuthCredentialWithPniZkcPresentation> for AnyAuthCredentialPresentation {
    fn from(presentation: AuthCredentialWithPniZkcPresentation) -> Self {
        Self::V4(presentation)
    }
}
