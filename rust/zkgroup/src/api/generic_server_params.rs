//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use partial_default::PartialDefault;
use serde::{Deserialize, Serialize};

use crate::common::serialization::VersionByte;
use crate::{RandomnessBytes, ZkGroupDeserializationFailure};

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialDefault, derive_more::TryFrom)]
#[try_from(repr)]
pub enum GenericServerParamsVersion {
    #[partial_default]
    Legacy = 0,
    Standard = 1,
}

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct GenericServerSecretParamsLegacy {
    version: VersionByte<{ GenericServerParamsVersion::Legacy as u8 }>,
    pub(crate) credential_key:
        zkcredential::credentials::CredentialKeyPair<zkcredential::credentials::LegacyMode>,
}

impl GenericServerSecretParamsLegacy {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        Self {
            version: Default::default(),
            credential_key: zkcredential::credentials::CredentialKeyPair::generate(randomness),
        }
    }

    pub fn get_public_params(
        &self,
    ) -> GenericServerPublicParamsImpl<{ GenericServerParamsVersion::Legacy as u8 }> {
        GenericServerPublicParamsImpl {
            version: self.version,
            credential_key: self.credential_key.public_key().clone(),
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct GenericServerSecretParamsStandard {
    version: VersionByte<{ GenericServerParamsVersion::Standard as u8 }>,
    pub(crate) credential_key:
        zkcredential::credentials::CredentialKeyPair<zkcredential::credentials::StandardMode>,
}

impl GenericServerSecretParamsStandard {
    pub fn generate(randomness: RandomnessBytes) -> Self {
        Self {
            version: Default::default(),
            credential_key: zkcredential::credentials::CredentialKeyPair::generate(randomness),
        }
    }

    pub fn get_public_params(
        &self,
    ) -> GenericServerPublicParamsImpl<{ GenericServerParamsVersion::Standard as u8 }> {
        GenericServerPublicParamsImpl {
            version: self.version,
            credential_key: self.credential_key.public_key().clone(),
        }
    }
}

#[derive(Clone, Serialize, PartialDefault, derive_more::From)]
#[serde(untagged)]
pub enum GenericServerSecretParams {
    #[partial_default]
    V0(GenericServerSecretParamsLegacy),
    V1(GenericServerSecretParamsStandard),
}

impl GenericServerSecretParams {
    pub fn get_public_params(&self) -> GenericServerPublicParams {
        match self {
            GenericServerSecretParams::V0(params) => params.get_public_params().into(),
            GenericServerSecretParams::V1(params) => params.get_public_params().into(),
        }
    }
}

impl TryFrom<&'_ [u8]> for GenericServerSecretParams {
    type Error = ZkGroupDeserializationFailure;
    fn try_from(bytes: &[u8]) -> Result<Self, ZkGroupDeserializationFailure> {
        match bytes
            .first()
            .and_then(|&v| v.try_into().ok())
            .ok_or(ZkGroupDeserializationFailure::new::<Self>())?
        {
            GenericServerParamsVersion::Legacy => {
                crate::deserialize::<GenericServerSecretParamsLegacy>(bytes).map(Self::V0)
            }
            GenericServerParamsVersion::Standard => {
                crate::deserialize::<GenericServerSecretParamsStandard>(bytes).map(Self::V1)
            }
        }
    }
}

// zkcredential public keys don't have different modes, but it's still useful to track how they were
// generated so that we can early-exit if a client uses public params that definitely won't match a
// given credential.
#[derive(Clone, Serialize, Deserialize, PartialDefault)]
pub struct GenericServerPublicParamsImpl<const V: u8> {
    version: VersionByte<V>,
    pub(crate) credential_key: zkcredential::credentials::CredentialPublicKey,
}

#[derive(Clone, Serialize, PartialDefault, derive_more::From)]
#[serde(untagged)]
pub enum GenericServerPublicParams {
    #[partial_default]
    V0(GenericServerPublicParamsImpl<{ GenericServerParamsVersion::Legacy as u8 }>),
    V1(GenericServerPublicParamsImpl<{ GenericServerParamsVersion::Standard as u8 }>),
}

impl TryFrom<&'_ [u8]> for GenericServerPublicParams {
    type Error = ZkGroupDeserializationFailure;
    fn try_from(bytes: &[u8]) -> Result<Self, ZkGroupDeserializationFailure> {
        match bytes
            .first()
            .and_then(|&v| v.try_into().ok())
            .ok_or(ZkGroupDeserializationFailure::new::<Self>())?
        {
            GenericServerParamsVersion::Legacy => crate::deserialize(bytes).map(Self::V0),
            GenericServerParamsVersion::Standard => crate::deserialize(bytes).map(Self::V1),
        }
    }
}
