//
// Copyright (C) 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;

pub trait Lookup<K, V> {
    /// Retrieve the value for a key in the map if one is present.
    fn lookup<'a>(&'a self, key: &'a K) -> Option<&'a V>;
}

/// Like [`Lookup`] but returns a pair of references.
pub trait LookupPair<K, V1, V2> {
    /// Retrieve both values if the key is present.
    fn lookup_pair<'a>(&'a self, key: &'a K) -> Option<(&'a V1, &'a V2)>;
}

impl<K, Q, V, W> Lookup<Q, W> for HashMap<K, V>
where
    Q: Eq + Hash,
    K: Eq + Hash,
    K: Borrow<Q>,
    V: AsRef<W>,
{
    fn lookup(&self, key: &Q) -> Option<&W> {
        HashMap::get(self, key).map(AsRef::as_ref)
    }
}

// The `serde::Serialize` supertrait isn't needed for anything but it simplifies
// using the `serde::Serialize` derive macro on types that are parameterized
// over `M: Method`. The macro's heuristic assumes that all type parameters must
// implement `serde::Serialize`. That's not correct in this case but it's
// simpler to just roll with it since the no-op implementations can be trivially
// derived.
pub trait Method: serde::Serialize + 'static {
    type Value<T: Debug + serde::Serialize>: Debug + serde::Serialize;
    type BoxedValue<T: Debug + serde::Serialize>: Debug + serde::Serialize;
    type List<T: Debug>: Extend<T> + Default + Debug;

    fn value<T: Debug + serde::Serialize>(value: T) -> Self::Value<T>;
    fn boxed_value<T: Debug + serde::Serialize>(value: T) -> Self::BoxedValue<T>;
}

#[derive(serde::Serialize)]
pub enum ValidateOnly {}

#[derive(Default, Debug)]
pub struct ValidateOnlyList;

impl<T> Extend<T> for ValidateOnlyList {
    fn extend<It: IntoIterator<Item = T>>(&mut self, iter: It) {
        iter.into_iter().for_each(|_| ())
    }
}

impl Method for ValidateOnly {
    type Value<T: Debug + serde::Serialize> = ();
    type BoxedValue<T: Debug + serde::Serialize> = ();
    type List<T: Debug> = ValidateOnlyList;

    fn value<T: Debug + serde::Serialize>(_value: T) -> Self::Value<T> {}
    fn boxed_value<T: Debug + serde::Serialize>(_value: T) -> Self::BoxedValue<T> {}
}

#[derive(serde::Serialize)]
pub enum Store {}

impl Method for Store {
    type Value<T: Debug + serde::Serialize> = T;
    type BoxedValue<T: Debug + serde::Serialize> = Box<T>;
    type List<T: Debug> = Vec<T>;

    fn value<T: Debug + serde::Serialize>(value: T) -> Self::Value<T> {
        value
    }
    fn boxed_value<T: Debug + serde::Serialize>(value: T) -> Self::BoxedValue<T> {
        Box::new(value)
    }
}
