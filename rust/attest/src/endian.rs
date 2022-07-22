//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::{TryFrom, TryInto};

use hex::FromHex;

#[derive(Debug)]
#[repr(C, packed)]
pub(crate) struct UInt16LE {
    bytes: [u8; 2],
}

impl UInt16LE {
    pub fn value(&self) -> u16 {
        u16::from_le_bytes(self.bytes)
    }
}

impl From<u16> for UInt16LE {
    fn from(x: u16) -> Self {
        Self {
            bytes: x.to_le_bytes(),
        }
    }
}

#[derive(Debug)]
#[repr(C, packed)]
pub(crate) struct UInt32LE {
    bytes: [u8; 4],
}

impl UInt32LE {
    pub fn value(&self) -> u32 {
        u32::from_le_bytes(self.bytes)
    }
}

impl From<u32> for UInt32LE {
    fn from(x: u32) -> Self {
        Self {
            bytes: x.to_le_bytes(),
        }
    }
}

impl TryFrom<&[u8]> for UInt32LE {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: value.try_into()?,
        })
    }
}

impl FromHex for UInt32LE {
    type Error = hex::FromHexError;
    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Ok(Self {
            bytes: <[u8; 4]>::from_hex(hex)?,
        })
    }
}

#[derive(Debug)]
#[repr(C, packed)]
pub(crate) struct UInt64LE {
    bytes: [u8; 8],
}
