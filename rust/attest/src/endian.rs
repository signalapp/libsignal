//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[derive(Debug)]
#[repr(C, packed)]
pub(crate) struct UInt16LE {
    bytes: [u8; 2],
}

impl UInt16LE {
    #[cfg(test)] // currently only used in tests
    pub fn value(&self) -> u16 {
        u16::from_le_bytes(self.bytes)
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

#[derive(Debug)]
#[repr(C, packed)]
pub(crate) struct UInt64LE {
    bytes: [u8; 8],
}
