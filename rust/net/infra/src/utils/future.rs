//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::pin::Pin;

use pin_project::pin_project;

/// [`Future`] that delegates to the inner `F: Future` or never resolves.
#[pin_project]
pub struct SomeOrPending<F>(#[pin] pub(crate) Option<F>);

impl<F> From<Option<F>> for SomeOrPending<F> {
    fn from(value: Option<F>) -> Self {
        Self(value)
    }
}

impl<F: Future> Future for SomeOrPending<F> {
    type Output = F::Output;

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match self.project().0.as_pin_mut() {
            Some(f) => f.poll(cx),
            None => std::task::Poll::Pending,
        }
    }
}
