use std::borrow::Borrow;
use std::collections::{hash_map, HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KeyExists;

pub trait Contains<K> {
    fn contains(&self, key: &K) -> bool;
}

pub trait Lookup<K, V>: Contains<K> {
    /// Retrieve the value for a key in the map if one is present.
    fn lookup<'a>(&'a self, key: &'a K) -> Option<&'a V>;
}

/// Like [`Lookup`] but returns a pair of references.
pub trait LookupPair<K, V1, V2>: Contains<K> {
    /// Retrieve both values if the key is present.
    fn lookup_pair<'a>(&'a self, key: &'a K) -> Option<(&'a V1, &'a V2)>;
}

pub trait Map<K, V>: Contains<K> + Default {
    /// Insert a key and value into the map if the key isn't already present.
    ///
    /// On failure, the map is unmodified.
    #[allow(dead_code)]
    fn insert(&mut self, key: K, value: V) -> Result<(), KeyExists>;
}

impl<K: Eq + Hash, V> Map<K, V> for HashMap<K, V> {
    fn insert(&mut self, key: K, value: V) -> Result<(), KeyExists> {
        match self.entry(key) {
            hash_map::Entry::Occupied(_) => Err(KeyExists),
            hash_map::Entry::Vacant(v) => {
                v.insert(value);
                Ok(())
            }
        }
    }
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

impl<K, Q, V> Contains<Q> for HashMap<K, V>
where
    Q: Eq + Hash,
    K: Eq + Hash,
    K: Borrow<Q>,
{
    fn contains(&self, key: &Q) -> bool {
        HashMap::contains_key(self, key)
    }
}

impl<K: Eq + Hash, V> Map<K, V> for HashSet<K> {
    fn insert(&mut self, key: K, _value: V) -> Result<(), KeyExists> {
        if self.insert(key) {
            Ok(())
        } else {
            // HashSet::insert guarantees the collection is unmodified here.
            Err(KeyExists)
        }
    }
}

impl<Q, K> Contains<Q> for HashSet<K>
where
    Q: Eq + Hash,
    K: Eq + Hash,
    K: Borrow<Q>,
{
    fn contains(&self, key: &Q) -> bool {
        HashSet::contains(self, key)
    }
}

// The `serde::Serialize` supertrait isn't needed for anything but it simplifies
// using the `serde::Serialize` derive macro on types that are parameterized
// over `M: Method`. The macro's heuristic assumes that all type parameters must
// implement `serde::Serialize`. That's not correct in this case but it's
// simpler to just roll with it since the no-op implementations can be trivially
// derived.
pub trait Method: serde::Serialize {
    type Value<T: Debug + serde::Serialize>: Debug + serde::Serialize;
    type BoxedValue<T: Debug>: Debug;
    type Map<K: Eq + Hash + Debug, V: Debug>: Map<K, V> + Debug;
    type List<T: Debug>: Extend<T> + Default + Debug;

    fn value<T: Debug + serde::Serialize>(value: T) -> Self::Value<T>;
    fn boxed_value<T: Debug>(value: T) -> Self::BoxedValue<T>;
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
    type BoxedValue<T: Debug> = ();
    type Map<K: Eq + Hash + Debug, V: Debug> = HashSet<K>;
    type List<T: Debug> = ValidateOnlyList;

    fn value<T: Debug + serde::Serialize>(_value: T) -> Self::Value<T> {}
    fn boxed_value<T: Debug>(_value: T) -> Self::BoxedValue<T> {}
}

#[derive(serde::Serialize)]
pub enum Store {}

impl Method for Store {
    type Value<T: Debug + serde::Serialize> = T;
    type BoxedValue<T: Debug> = Box<T>;
    type Map<K: Eq + Hash + Debug, V: Debug> = HashMap<K, V>;
    type List<T: Debug> = Vec<T>;

    fn value<T: Debug + serde::Serialize>(value: T) -> Self::Value<T> {
        value
    }
    fn boxed_value<T: Debug>(value: T) -> Self::BoxedValue<T> {
        Box::new(value)
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use test_case::test_case;

    use super::*;

    struct Validate;
    struct Store;

    trait MethodGen {
        type Method: Method;
    }

    impl MethodGen for Validate {
        type Method = ValidateOnly;
    }

    impl MethodGen for Store {
        type Method = super::Store;
    }

    #[test_case(Validate)]
    #[test_case(Store)]
    fn insert_new_key<G: MethodGen>(_: G) {
        let mut map = <G::Method as Method>::Map::default();

        const FIRST_KEY: usize = 123;
        const SECOND_KEY: usize = 456;

        assert!(!map.contains(&FIRST_KEY));
        assert!(!map.contains(&SECOND_KEY));

        map.insert(FIRST_KEY, "abc").expect("no conflict");
        map.insert(SECOND_KEY, "other").expect("no conflict");

        assert!(map.contains(&FIRST_KEY));
        assert!(map.contains(&SECOND_KEY));
    }

    #[test_case(Validate)]
    #[test_case(Store)]
    fn insert_conflict<G: MethodGen>(_: G) {
        let mut map = <G::Method as Method>::Map::default();

        const KEY: usize = 123;

        map.insert(KEY, "abc").expect("no conflict");
        assert_matches!(map.insert(KEY, "other"), Err(KeyExists));
    }
}
