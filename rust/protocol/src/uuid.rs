//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::array::TryFromSliceError;
use std::convert::TryFrom;

#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug)]
pub struct Uuid([u8; 16]);

impl AsRef<[u8; 16]> for Uuid {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for Uuid {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl From<u128> for Uuid {
    fn from(bits: u128) -> Self {
        Self(bits.to_be_bytes())
    }
}

impl TryFrom<&[u8]> for Uuid {
    type Error = TryFromSliceError;

    fn try_from(slice: &[u8]) -> Result<Uuid, TryFromSliceError> {
        <[u8; 16]>::try_from(slice).map(Uuid::from)
    }
}

impl From<Uuid> for [u8; 16] {
    fn from(uuid: Uuid) -> Self {
        uuid.0
    }
}

impl From<Uuid> for Vec<u8> {
    fn from(uuid: Uuid) -> Self {
        uuid.0.into()
    }
}
