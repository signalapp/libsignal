//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;

/// A wrapper type that indicates that `T` should be converted to/from `P`
/// across the bridge.
///
/// This should not be used to convert user-provided data since the error messages are not very friendly. A failure to
/// convert from `P` to `T` indicates a bug in libsignal or in application code.
#[derive(derive_more::Deref)]
pub struct AsType<T, P>(#[deref] T, PhantomData<P>);

impl<T, P> AsType<T, P> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T, P> From<T> for AsType<T, P> {
    fn from(value: T) -> Self {
        Self(value, PhantomData)
    }
}
