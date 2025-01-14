use partial_default::PartialDefault;
use serde::{Serialize, Serializer};

use crate::api;
use crate::auth::AuthCredentialWithPniZkcPresentation;
use crate::common::constants::*;
use crate::common::errors::*;
use crate::common::simple_types::*;

#[derive(derive_more::From)]
pub enum AnyAuthCredentialPresentation {
    V4(AuthCredentialWithPniZkcPresentation),
}

#[repr(u8)]
#[derive(
    Copy, Clone, Debug, PartialDefault, num_enum::IntoPrimitive, num_enum::TryFromPrimitive,
)]
enum PresentationVersion {
    // V1-V3 are no longer supported.
    #[partial_default]
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
            PresentationVersion::V4 => Ok(crate::deserialize::<
                AuthCredentialWithPniZkcPresentation,
            >(presentation_bytes)?
            .into()),
        }
    }

    pub fn get_aci_ciphertext(&self) -> api::groups::UuidCiphertext {
        match self {
            AnyAuthCredentialPresentation::V4(presentation) => presentation.aci_ciphertext(),
        }
    }

    pub fn get_pni_ciphertext(&self) -> api::groups::UuidCiphertext {
        match self {
            AnyAuthCredentialPresentation::V4(presentation) => presentation.pni_ciphertext(),
        }
    }

    pub fn get_redemption_time(&self) -> Timestamp {
        match self {
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
            AnyAuthCredentialPresentation::V4(presentation) => presentation.serialize(serializer),
        }
    }
}
