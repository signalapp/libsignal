//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub(crate) type UInt16LE = zerocopy::little_endian::U16;
pub(crate) type UInt32LE = zerocopy::little_endian::U32;
pub(crate) type UInt64LE = zerocopy::little_endian::U64;

static_assertions::assert_eq_align!(u8, UInt16LE);
static_assertions::assert_eq_size!(u16, UInt16LE);

static_assertions::assert_eq_align!(u8, UInt32LE);
static_assertions::assert_eq_size!(u32, UInt32LE);

static_assertions::assert_eq_align!(u8, UInt64LE);
static_assertions::assert_eq_size!(u64, UInt64LE);
