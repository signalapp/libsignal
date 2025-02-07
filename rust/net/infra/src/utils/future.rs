//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

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

/// Tries to get at least one, and possibly two `Some(_)` results from the given
/// futures, if they complete within a `delay` interval from each other.
///
/// Given two futures that return `Option<A/B>`, this function tries to drive
/// both of them to completion. If one completes with `Some(res)`, then the
/// other one is given `delay` time to finish, too. The `delay` does not apply
/// if a future returns `None`. Depending on the timing and results of the
/// futures, this function may return any combination of `(Some(r1)|None, Some(r2)|None)`.
pub(crate) async fn results_within_interval<A, B>(
    a: impl Future<Output = Option<A>>,
    b: impl Future<Output = Option<B>>,
    delay: Duration,
) -> (Option<A>, Option<B>) {
    tokio::pin!(a, b);
    tokio::select! {
        a_res = &mut a => match a_res {
            None => (None, b.await),
            Some(a_res) => (Some(a_res), tokio::time::timeout(delay, b).await.ok().flatten()),
        },
        b_res = &mut b => match b_res {
            None => (a.await, None),
            Some(b_res) => (tokio::time::timeout(delay, a).await.ok().flatten(), Some(b_res)),
        },
    }
}
