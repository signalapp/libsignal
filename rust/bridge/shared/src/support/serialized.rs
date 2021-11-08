//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryFrom;
use std::ops::Deref;

/// A trait representing arrays, for use in other traits and generics.
pub(crate) trait Array<Element>: AsRef<[Element]> {
    const LEN: usize;
}
impl<T, const LEN: usize> Array<T> for [T; LEN] {
    const LEN: usize = LEN;
}

/// Represents a type that can be serialized into an array.
pub(crate) trait FixedLengthBincodeSerializable: 'static {
    /// Should be an actual byte array type, like `[u8; 7]`.
    type Array: Array<u8> + for<'a> TryFrom<&'a [u8], Error = std::array::TryFromSliceError>;
}

/// A wrapper type that indicates that `T` should be serialized across the bridges.
pub(crate) struct Serialized<T>(T);

impl<T> Serialized<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Deref for Serialized<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> From<T> for Serialized<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}
