use std::collections::{hash_map, HashMap, HashSet};
use std::fmt::Debug;
use std::hash::Hash;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KeyExists;

pub trait Map<K, V>: Default {
    /// Insert a key and value into the map if the key isn't already present.
    ///
    /// On failure, the map is unmodified.
    fn insert(&mut self, key: K, value: V) -> Result<(), KeyExists>;
    fn contains(&self, key: &K) -> bool;
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
    fn contains(&self, key: &K) -> bool {
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

    fn contains(&self, key: &K) -> bool {
        HashSet::contains(self, key)
    }
}

pub trait Method {
    type Value<T: Debug>: Debug;
    type Map<K: Eq + Hash + Debug, V: Debug>: Map<K, V> + Debug;

    fn value<T: Debug>(value: T) -> Self::Value<T>;
}

pub enum ValidateOnly {}

impl Method for ValidateOnly {
    type Value<T: Debug> = ();
    type Map<K: Eq + Hash + Debug, V: Debug> = HashSet<K>;

    fn value<T: Debug>(_value: T) -> Self::Value<T> {}
}

pub enum Store {}

impl Method for Store {
    type Value<T: Debug> = T;
    type Map<K: Eq + Hash + Debug, V: Debug> = HashMap<K, V>;

    fn value<T: Debug>(value: T) -> Self::Value<T> {
        value
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
