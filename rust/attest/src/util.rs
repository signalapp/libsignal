//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto;

/// Removes a trailing null byte, if one exists
pub(crate) fn strip_trailing_null_byte(bytes: &mut &[u8]) {
    *bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
}

/// Reads a little-endian u64 from the slice and advances it by 8 bytes.
///
/// Note: Caller must ensure the slice is large enough
pub(crate) fn read_u64_le(bytes: &mut &[u8]) -> u64 {
    let (u64_bytes, remainder) = bytes.split_at(8);
    *bytes = remainder;

    u64::from_le_bytes(u64_bytes.try_into().expect("correct size"))
}

/// Removes a slice of `size` from the front of `bytes` and returns it
///
/// Note: Caller must ensure that the slice is large enough
pub(crate) fn read_bytes<'a>(bytes: &'a mut &[u8], size: usize) -> &'a [u8] {
    let (front, rest) = bytes.split_at(size);
    *bytes = rest;
    front
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_strip_trailing_null_byte() {
        let mut slice_with_trailing_null: &[u8] = &[2u8, 0];
        strip_trailing_null_byte(&mut slice_with_trailing_null);
        assert_eq!(&[2u8], slice_with_trailing_null);

        let mut no_trailing_null: &[u8] = &[3u8];
        strip_trailing_null_byte(&mut no_trailing_null);
        assert_eq!(&[3u8], no_trailing_null);

        let mut empty_slice: &[u8] = &[];
        strip_trailing_null_byte(&mut empty_slice);
        let expected: &[u8] = &[];
        assert_eq!(expected, empty_slice);
    }

    #[test]
    fn test_read_u64_le() {
        let mut one: &[u8] = &[1u8, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(1, read_u64_le(&mut one));
        assert_eq!(0, one.len());
    }

    #[test]
    fn test_read_bytes() {
        let mut slice: &[u8] = &[0u8, 1, 2, 3, 4, 5];

        let front = read_bytes(&mut slice, 2);

        assert_eq!(&[0u8, 1], front);
        assert_eq!(&[2u8, 3, 4, 5], slice);
    }
}
