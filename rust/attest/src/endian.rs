//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::{TryFrom, TryInto};

use hex::FromHex;

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub(crate) struct UInt16LE {
    bytes: [u8; 2],
}

static_assertions::assert_eq_align!(u8, UInt16LE);
static_assertions::assert_eq_size!(u16, UInt16LE);

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

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub(crate) struct UInt32LE {
    bytes: [u8; 4],
}

static_assertions::assert_eq_align!(u8, UInt32LE);
static_assertions::assert_eq_size!(u32, UInt32LE);

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

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub(crate) struct UInt64LE {
    bytes: [u8; 8],
}

static_assertions::assert_eq_align!(u8, UInt64LE);
static_assertions::assert_eq_size!(u64, UInt64LE);
