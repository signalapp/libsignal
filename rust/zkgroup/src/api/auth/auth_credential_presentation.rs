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
    V3(AuthCredentialWithPniPresentation),
    V4(AuthCredentialWithPniZkcPresentation),
}

#[repr(u8)]
#[derive(
    Copy, Clone, Debug, PartialDefault, num_enum::IntoPrimitive, num_enum::TryFromPrimitive,
)]
enum PresentationVersion {
    // V1 and V2 are no longer supported.
    #[partial_default]
    V3 = PRESENTATION_VERSION_3,
    V4 = PRESENTATION_VERSION_4,
}

impl AnyAuthCredentialPresentation {
    pub fn new(presentation_bytes: &[u8]) -> Result<Self, ZkGroupDeserializationFailure> {
        let first = *presentation_bytes
            .first()
            .ok_or(ZkGroupDeserializationFailure::new::<Self>())?;
        let version = PresentationVersion::try_from(first)
            .map_err(|_| ZkGroupDeserializationFailure::new::<Self>())?;
        match version {
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
            AnyAuthCredentialPresentation::V3(presentation) => presentation.get_aci_ciphertext(),
            AnyAuthCredentialPresentation::V4(presentation) => presentation.aci_ciphertext(),
        }
    }

    pub fn get_pni_ciphertext(&self) -> Option<api::groups::UuidCiphertext> {
        // Even though the current implementation of this function could return
        // a non-optional value, we might want to support PNI-less credentials
        // in the future. Keep the optionality in the signature to make it
        // easier to transition when that happens.
        Some(match self {
            AnyAuthCredentialPresentation::V3(presentation) => presentation.get_pni_ciphertext(),
            AnyAuthCredentialPresentation::V4(presentation) => presentation.pni_ciphertext(),
        })
    }

    pub fn get_redemption_time(&self) -> Timestamp {
        match self {
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
            AnyAuthCredentialPresentation::V3(presentation) => presentation.serialize(serializer),
            AnyAuthCredentialPresentation::V4(presentation) => presentation.serialize(serializer),
        }
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
