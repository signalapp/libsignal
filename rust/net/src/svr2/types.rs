//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::{NonZeroU8, NonZeroU32};

use super::Error;

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
pub struct MaxTries(NonZeroU8);

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[error("Max tries is out of [1, 255] range")]
pub struct InvalidMaxTries;

impl From<InvalidMaxTries> for Error {
    fn from(value: InvalidMaxTries) -> Self {
        Self::Protocol(value.to_string())
    }
}

impl From<MaxTries> for u32 {
    fn from(value: MaxTries) -> Self {
        value.0.get().into()
    }
}

impl TryFrom<u32> for MaxTries {
    type Error = InvalidMaxTries;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match NonZeroU32::try_from(value).and_then(NonZeroU8::try_from) {
            Ok(value) => Ok(MaxTries(value)),
            Err(_) => Err(InvalidMaxTries),
        }
    }
}

impl MaxTries {
    pub const fn new(value: u8) -> Result<Self, InvalidMaxTries> {
        if let Some(value) = NonZeroU8::new(value) {
            Ok(MaxTries(value))
        } else {
            Err(InvalidMaxTries)
        }
    }
}

pub type Svr2Data = StorableData<16, 48>;

/// A newtype wrapper for `Vec<u8>` only allowing the sizes in range [M, N]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorableData<const M: usize, const N: usize> {
    inner: Vec<u8>,
    _lb: [(); M],
    _ub: [(); N],
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[error("Invalid data size. {0} not in [{1}, {2}]")]
pub struct InvalidDataSize(usize, usize, usize);

impl From<InvalidDataSize> for Error {
    fn from(value: InvalidDataSize) -> Self {
        Self::Protocol(value.to_string())
    }
}

impl<const M: usize, const N: usize> StorableData<M, N> {
    pub(crate) fn new_unchecked(data: Vec<u8>) -> Self {
        Self {
            inner: data,
            _lb: [(); M],
            _ub: [(); N],
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.inner
    }
}

impl<const M: usize, const N: usize> AsRef<[u8]> for StorableData<M, N> {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

impl<const M: usize, const N: usize> TryFrom<Vec<u8>> for StorableData<M, N> {
    type Error = InvalidDataSize;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if (M..=N).contains(&value.len()) {
            Ok(Self::new_unchecked(value))
        } else {
            Err(InvalidDataSize(value.len(), M, N))
        }
    }
}

impl<const M: usize, const N: usize> TryFrom<Box<[u8]>> for StorableData<M, N> {
    type Error = InvalidDataSize;

    fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
        Self::try_from(value.into_vec())
    }
}

impl<const M: usize, const N: usize> TryFrom<&[u8]> for StorableData<M, N> {
    type Error = InvalidDataSize;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from(value.to_vec())
    }
}

#[cfg(test)]
mod test {
    use test_case::test_matrix;

    use super::*;

    type TestData = StorableData<2, 4>;

    #[test_matrix([2, 3, 4])]
    fn storable_data_valid_size(size: usize) {
        TestData::try_from(vec![42; size]).expect("success");
    }

    #[test_matrix([0, 1, 5])]
    fn storable_data_invalid_size(size: usize) {
        TestData::try_from(vec![42; size]).expect_err("over or under");
    }
}
