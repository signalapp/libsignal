//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use num_enum::TryFromPrimitive;
use partial_default::PartialDefault;
use serde::Serialize;

mod v0;
pub use v0::{AuthCredentialWithPniV0, AuthCredentialWithPniV0Response};
mod zkc;
pub use zkc::{
    AuthCredentialWithPniZkc, AuthCredentialWithPniZkcPresentation,
    AuthCredentialWithPniZkcResponse,
};

use crate::ZkGroupDeserializationFailure;

#[derive(Clone, PartialDefault)]
pub enum AuthCredentialWithPni {
    #[partial_default]
    V0(AuthCredentialWithPniV0),
    Zkc(AuthCredentialWithPniZkc),
}

#[derive(Clone, PartialDefault)]
pub enum AuthCredentialWithPniResponse {
    #[partial_default]
    V0(AuthCredentialWithPniV0Response),
    Zkc(AuthCredentialWithPniZkcResponse),
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialDefault, TryFromPrimitive)]
pub enum AuthCredentialWithPniVersion {
    #[partial_default]
    V0 = 0,
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
            AuthCredentialWithPniVersion::V0 => {
                crate::common::serialization::deserialize(bytes).map(Self::V0)
            }
            AuthCredentialWithPniVersion::Zkc => {
                crate::common::serialization::deserialize(bytes).map(Self::Zkc)
            }
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
            AuthCredentialWithPniVersion::V0 => {
                crate::common::serialization::deserialize(bytes).map(Self::V0)
            }
            AuthCredentialWithPniVersion::Zkc => {
                crate::common::serialization::deserialize(bytes).map(Self::Zkc)
            }
        }
    }
}

impl From<AuthCredentialWithPniV0> for AuthCredentialWithPni {
    fn from(value: AuthCredentialWithPniV0) -> Self {
        Self::V0(value)
    }
}

impl From<AuthCredentialWithPniV0Response> for AuthCredentialWithPniResponse {
    fn from(value: AuthCredentialWithPniV0Response) -> Self {
        Self::V0(value)
    }
}

impl From<AuthCredentialWithPniZkc> for AuthCredentialWithPni {
    fn from(value: AuthCredentialWithPniZkc) -> Self {
        Self::Zkc(value)
    }
}

impl From<AuthCredentialWithPniZkcResponse> for AuthCredentialWithPniResponse {
    fn from(value: AuthCredentialWithPniZkcResponse) -> Self {
        Self::Zkc(value)
    }
}

impl Serialize for AuthCredentialWithPni {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            Self::V0(v) => v.serialize(serializer),
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
            Self::V0(v) => v.serialize(serializer),
            Self::Zkc(z) => z.serialize(serializer),
        }
    }
}
