//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use derive_where::derive_where;
use itertools::Itertools;

use crate::backup::serialize::SerializeOrder;

/// Unordered list of `T`s.
///
/// `UnorderedList<T>` implements [`serde::Serialize`] by serializing to a
/// canonical order, which requires `T: SerializeOrder`.
#[derive(Clone, Debug)]
#[derive_where(Default)]
#[cfg_attr(test, derive(PartialEq))]
pub struct UnorderedList<T>(pub(crate) Vec<T>);

impl<T> serde::Serialize for UnorderedList<T>
where
    T: serde::Serialize + SerializeOrder,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut items = self.0.iter().collect_vec();
        items.sort_by(|l, r| l.serialize_cmp(r));

        serializer.collect_seq(items)
    }
}

impl<T> FromIterator<T> for UnorderedList<T> {
    fn from_iter<It: IntoIterator<Item = T>>(iter: It) -> Self {
        Self(Vec::from_iter(iter))
    }
}

impl<T> IntoIterator for UnorderedList<T> {
    type Item = T;

    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T> UnorderedList<T> {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
impl<T> From<Vec<T>> for UnorderedList<T> {
    fn from(value: Vec<T>) -> Self {
        Self(value)
    }
}
