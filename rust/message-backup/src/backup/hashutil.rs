//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::hash::{Hash, Hasher};

/// A hasher that assumes its input is already uniformly random, or close enough to it.
#[derive(Default)]
pub(crate) struct AssumedRandomInputHasher(u64);

impl AssumedRandomInputHasher {
    pub fn map_with_capacity<K, V>(
        capacity: usize,
    ) -> HashMap<K, V, std::hash::BuildHasherDefault<Self>> {
        HashMap::with_capacity_and_hasher(capacity, Default::default())
    }
}

impl Hasher for AssumedRandomInputHasher {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        // TODO: replace with slice::first_chunk once our MSRV is 1.77+
        fn first_chunk<const N: usize>(slice: &[u8]) -> Option<&[u8; N]> {
            if slice.len() < N {
                None
            } else {
                Some(slice[..N].try_into().unwrap())
            }
        }

        let Some(u64_bytes) = first_chunk(bytes) else {
            // Assume we'll get at least one input that's at least 8 bytes long.
            return;
        };
        self.0 = u64::from_le_bytes(*u64_bytes);
    }
}

/// A wrapper around byte arrays with more Hasher-friendly Hash implementation than Rust's default.
#[derive(PartialEq, Eq)]
pub(crate) struct HashBytesAllAtOnce<T>(T);

impl<const N: usize> From<[u8; N]> for HashBytesAllAtOnce<[u8; N]> {
    fn from(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> Hash for HashBytesAllAtOnce<[u8; N]> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write(&self.0);
    }
}
