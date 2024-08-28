//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::SystemTime;

use boring_signal::asn1::Asn1Time;
use libc::time_t;

/// A replacement for [`std::collections::HashMap`] that performs linear lookups.
///
/// This can be used in place of `HashMap` for supporting lookup in `const`
/// arrays. For small `N`, the linear search will be faster than a hash lookup.
pub(crate) struct SmallMap<K, V, const N: usize>([(K, V); N]);

impl<K, V, const N: usize> SmallMap<K, V, N> {
    /// The maximum number of elements allowed in a `SmallMap`.
    const MAX_SIZE: usize = 10;

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

/// Removes a slice of `size` from the front of `bytes` and returns it
///
/// Note: Caller must ensure that the slice is large enough
pub(crate) fn read_bytes<'a>(bytes: &mut &'a [u8], size: usize) -> &'a [u8] {
    let (front, rest) = bytes.split_at(size);
    *bytes = rest;
    front
}

/// Removes `std::mem::size_of<T>()` bytes from the front of `bytes` and returns it as a `T`.
///
/// Returns `None` and leaves `bytes` unchanged if it isn't long enough.
pub(crate) fn read_from_bytes<T: zerocopy::FromBytes>(bytes: &mut &[u8]) -> Option<T> {
    let front = T::read_from_prefix(bytes)?;
    *bytes = &bytes[std::mem::size_of::<T>()..];
    Some(front)
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
    use crate::endian::{UInt16LE, UInt32LE, UInt64LE};

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
    fn test_read_from_bytes() {
        let mut input: &[u8] = &[1u8, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0];
        #[derive(Debug, PartialEq, zerocopy::FromBytes, zerocopy::FromZeroes)]
        #[repr(C)]
        struct Values {
            one: UInt64LE,
            two: UInt32LE,
            three: UInt16LE,
        }

        assert_eq!(
            Some(Values {
                one: 1.into(),
                two: 2.into(),
                three: 3.into(),
            }),
            read_from_bytes(&mut input)
        );
        assert_eq!(input, &[] as &[u8]);
    }

    #[test]
    fn test_read_bytes() {
        let mut slice: &[u8] = &[0u8, 1, 2, 3, 4, 5];

        let front = read_bytes(&mut slice, 2);

        assert_eq!(&[0u8, 1], front);
        assert_eq!(&[2u8, 3, 4, 5], slice);
    }
}
