//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_core::{Aci, Pni};
use num_enum::TryFromPrimitive;
use partial_default::PartialDefault;
use serde::Serialize;

use crate::auth::AnyAuthCredentialPresentation;
use crate::groups::GroupSecretParams;
use crate::{
    RandomnessBytes, ServerPublicParams, ZkGroupDeserializationFailure, ZkGroupVerificationFailure,
};

mod zkc;
pub use zkc::{
    AuthCredentialWithPniZkc, AuthCredentialWithPniZkcPresentation,
    AuthCredentialWithPniZkcResponse,
};

#[derive(Clone, PartialDefault, derive_more::From)]
pub enum AuthCredentialWithPni {
    #[partial_default]
    Zkc(AuthCredentialWithPniZkc),
}

#[derive(Clone, PartialDefault, derive_more::From)]
pub enum AuthCredentialWithPniResponse {
    #[partial_default]
    Zkc(AuthCredentialWithPniZkcResponse),
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialDefault, TryFromPrimitive)]
pub enum AuthCredentialWithPniVersion {
    #[partial_default]
    Zkc = 3,
}

impl AuthCredentialWithPni {
    pub fn new(bytes: &[u8]) -> Result<Self, ZkGroupDeserializationFailure> {
        let first = bytes
            .first()
            .ok_or_else(ZkGroupDeserializationFailure::new::<Self>)?;
        let version = AuthCredentialWithPniVersion::try_from(*first)
            .map_err(|_| ZkGroupDeserializationFailure::new::<Self>())?;
        match version {
            AuthCredentialWithPniVersion::Zkc => {
                crate::common::serialization::deserialize(bytes).map(Self::Zkc)
            }
        }
    }

    pub fn present(
        &self,
        public_params: &ServerPublicParams,
        group_secret_params: &GroupSecretParams,
        randomness: RandomnessBytes,
    ) -> AnyAuthCredentialPresentation {
        match self {
            Self::Zkc(credential) => AnyAuthCredentialPresentation::V4(credential.present(
                public_params,
                group_secret_params,
                randomness,
            )),
        }
    }
}

impl AuthCredentialWithPniResponse {
    pub fn new(bytes: &[u8]) -> Result<Self, ZkGroupDeserializationFailure> {
        let first = bytes
            .first()
            .ok_or_else(ZkGroupDeserializationFailure::new::<Self>)?;
        let version = AuthCredentialWithPniVersion::try_from(*first)
            .map_err(|_| ZkGroupDeserializationFailure::new::<Self>())?;
        match version {
            AuthCredentialWithPniVersion::Zkc => {
                crate::common::serialization::deserialize(bytes).map(Self::Zkc)
            }
        }
    }

    pub fn receive(
        self,
        public_params: &ServerPublicParams,
        aci: Aci,
        pni: Pni,
        redemption_time: crate::Timestamp,
    ) -> Result<AuthCredentialWithPni, ZkGroupVerificationFailure> {
        match self {
            Self::Zkc(credential) => credential
                .receive(aci, pni, redemption_time, public_params)
                .map(AuthCredentialWithPni::Zkc),
        }
    }
}

impl Serialize for AuthCredentialWithPni {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Zkc(z) => z.serialize(serializer),
        }
    }
}

impl Serialize for AuthCredentialWithPniResponse {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::Zkc(z) => z.serialize(serializer),
        }
    }
}
