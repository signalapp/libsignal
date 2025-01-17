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
#[derive(Clone, Debug, derive_more::From, derive_more::IntoIterator)]
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

impl<T> UnorderedList<T> {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn iter(&self) -> std::slice::Iter<T> {
        self.0.iter()
    }
}
