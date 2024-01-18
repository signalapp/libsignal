//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use boring::asn1::Asn1Time;
use libc::time_t;

/// A replacement for [`std::collections::HashMap`] that performs linear lookups.
///
/// This can be used in place of `HashMap` for supporting lookup in `const`
/// arrays. For small `N`, the linear search will be faster than a hash lookup.
pub(crate) struct SmallMap<K, V, const N: usize>([(K, V); N]);

impl<K, V, const N: usize> SmallMap<K, V, N> {
    /// The maximum number of elements allowed in a `SmallMap`.
    const MAX_SIZE: usize = 5;

    /// Checks at compile-time (via `const`) that `N` is small enough.
    const CHECK_MAX_SIZE: () = assert!(
        N <= Self::MAX_SIZE,
        "use a HashMap for more than MAX_SIZE items"
    );

    /// Creates a new `SmallMap` with the given contents.
    pub(crate) const fn new(items: [(K, V); N]) -> Self {
        // Evaluate CHECK_MAX_SIZE; this will fail compilation if `N` is too
        // large.
        //
        // TODO(https://github.com/rust-lang/rust-clippy/issues/9048): Remove
        // the unnecessary #[allow].
        #[allow(clippy::let_unit_value)]
        let _: () = Self::CHECK_MAX_SIZE;
        Self(items)
    }

    /// Gets the value for the first key that matches `key`, or `None`.
    pub(crate) fn get<Q: PartialEq<K> + ?Sized>(&self, key: &Q) -> Option<&V> {
        self.0.iter().find_map(|(k, v)| (key == k).then_some(v))
    }
}

/// Removes a trailing null byte, if one exists
pub(crate) fn strip_trailing_null_byte(bytes: &mut &[u8]) {
    *bytes = bytes.strip_suffix(&[0]).unwrap_or(bytes);
}

/// Reads a little-endian u16 from the slice and advances it by 2 bytes.
///
/// Note: Caller must ensure the slice is large enough
pub(crate) fn read_u16_le(bytes: &mut &[u8]) -> u16 {
    let (u16_bytes, remainder) = bytes.split_at(2);
    *bytes = remainder;

    u16::from_le_bytes(u16_bytes.try_into().expect("correct size"))
}

/// Reads a little-endian u32 from the slice and advances it by 4 bytes.
///
/// Note: Caller must ensure the slice is large enough
pub(crate) fn read_u32_le(bytes: &mut &[u8]) -> u32 {
    let (u32_bytes, remainder) = bytes.split_at(4);
    *bytes = remainder;

    u32::from_le_bytes(u32_bytes.try_into().expect("correct size"))
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
pub(crate) fn read_bytes<'a>(bytes: &mut &'a [u8], size: usize) -> &'a [u8] {
    let (front, rest) = bytes.split_at(size);
    *bytes = rest;
    front
}

/// Removes a slice of `N` from the front of `bytes` and copies
/// it into an owned `[u8; N]`
///
/// Note: Caller must ensure the slice is large enough
pub(crate) fn read_array<const N: usize>(bytes: &mut &[u8]) -> [u8; N] {
    let mut res = [0u8; N];
    let (front, rest) = bytes.split_at(N);
    res.copy_from_slice(front);
    *bytes = rest;
    res
}

#[derive(Debug)]
pub(crate) struct FailedToConvertToAsn1Time;

pub(crate) fn system_time_to_asn1_time(
    timestamp: SystemTime,
) -> Result<Asn1Time, FailedToConvertToAsn1Time> {
    let epoch_duration = timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| FailedToConvertToAsn1Time)?;

    let t: time_t = epoch_duration
        .as_secs()
        .try_into()
        .map_err(|_| FailedToConvertToAsn1Time)?;

    Asn1Time::from_unix(t).map_err(|_| FailedToConvertToAsn1Time)
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
