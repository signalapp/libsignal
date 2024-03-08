//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ops::Index;

use serde::{Deserialize, Serialize};

/// Abstracts over fixed-length arrays (and similar types) with an element type `T`.
///
/// Provides `iter` and `Index` rather than `Deref` or `AsRef<[T]>` to allow for alternate forms of
/// indexing, for which exposing a slice could be confusing. See [`OneBased`].
pub trait ArrayLike<T>: Index<usize, Output = T> {
    const LEN: usize;
    fn create(create_element: impl FnMut() -> T) -> Self;
    fn iter(&self) -> std::slice::Iter<T>;
}

impl<T, const LEN: usize> ArrayLike<T> for [T; LEN] {
    const LEN: usize = LEN;
    fn create(mut create_element: impl FnMut() -> T) -> Self {
        [0; LEN].map(|_| create_element())
    }
    fn iter(&self) -> std::slice::Iter<T> {
        self[..].iter()
    }
}

/// A wrapper around an array or slice to use one-based indexing.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct OneBased<T>(pub T);

impl<T> Index<usize> for OneBased<T>
where
    T: Index<usize>,
{
    type Output = T::Output;
    fn index(&self, index: usize) -> &Self::Output {
        assert!(index > 0, "one-based index cannot be zero");
        &self.0[index - 1]
    }
}

impl<T, Ts> ArrayLike<T> for OneBased<Ts>
where
    Ts: ArrayLike<T>,
{
    const LEN: usize = Ts::LEN;

    fn create(create_element: impl FnMut() -> T) -> Self {
        OneBased(Ts::create(create_element))
    }

    fn iter(&self) -> std::slice::Iter<T> {
        self.0.iter()
    }
}

#[test]
fn test_one_based_indexing() {
    let array = OneBased([10, 20, 30]);
    assert_eq!(10, array[1]);
    assert_eq!(20, array[2]);
    assert_eq!(30, array[3]);
}

#[test]
#[should_panic]
fn test_one_based_indexing_with_zero() {
    let array = OneBased([10, 20, 30]);
    let _ = array[0];
}

#[test]
#[should_panic]
fn test_one_based_indexing_past_end() {
    let array = OneBased([10, 20, 30]);
    let _ = array[4];
}

#[test]
fn test_one_based_iter() {
    let array = OneBased([10, 20, 30]);
    assert_eq!(vec![10, 20, 30], array.iter().copied().collect::<Vec<_>>());
}
