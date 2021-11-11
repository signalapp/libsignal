//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::ops::Index;

pub trait ArrayLike<T>: AsRef<[T]> + Index<usize, Output = T> {
    const LEN: usize;
    fn create(create_element: impl FnMut() -> T) -> Self;
}

impl<T, const LEN: usize> ArrayLike<T> for [T; LEN] {
    const LEN: usize = LEN;
    fn create(mut create_element: impl FnMut() -> T) -> Self {
        [0; LEN].map(|_| create_element())
    }
}
