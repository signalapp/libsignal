//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;

use derive_where::derive_where;

/// A wrapper around [`intmap::IntMap`] that preserves type-safety for keys.
///
/// All methods forward to the underlying map unless otherwise specified.
#[derive(Debug)]
#[derive_where(Default)]
pub struct IntMap<K, V> {
    inner: intmap::IntMap<V>,
    _keys: PhantomData<K>,
}

/// Helper for [`IntMap`] to get a numeric key from an arbitrary type.
pub trait IntKey {
    fn int_key(&self) -> u64;
}

impl<K: IntKey, V> IntMap<K, V> {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: intmap::IntMap::with_capacity(capacity),
            _keys: PhantomData,
        }
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.inner.get(key.int_key())
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.inner.get_mut(key.int_key())
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.inner.insert(key.int_key(), value)
    }

    pub fn entry(&mut self, key: K) -> intmap::Entry<'_, V> {
        self.inner.entry(key.int_key())
    }

    pub fn values(&self) -> impl Iterator<Item = &'_ V> {
        self.inner.values()
    }

    pub fn into_values(self) -> impl Iterator<Item = V> {
        self.inner.into_iter().map(|(_k, v)| v)
    }

    /// Like `into_iter`, but [`IntKey`] doesn't provide a way to map the keys back to the original
    /// type.
    #[cfg(test)]
    pub fn into_iter_with_raw_keys(self) -> impl Iterator<Item = (u64, V)> {
        self.inner.into_iter()
    }
}

impl<K: IntKey, V> FromIterator<(K, V)> for IntMap<K, V> {
    fn from_iter<T: IntoIterator<Item = (K, V)>>(iter: T) -> Self {
        Self {
            inner: iter.into_iter().map(|(k, v)| (k.int_key(), v)).collect(),
            _keys: PhantomData,
        }
    }
}
