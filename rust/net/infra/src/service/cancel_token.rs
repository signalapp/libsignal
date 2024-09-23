//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use derive_where::derive_where;
use tokio::sync::watch::{Receiver as WatchReceiver, Sender as WatchSender};

/// Like [`tokio_util::sync::CancellationToken`] but with a reason attached.
///
/// A clonable token that can be used to asynchronously watch for and broadcast
/// a cancellation reason from multiple threads. If there are multiple attempts
/// to cancel the token, the first one wins.
#[derive_where(Clone)]
#[derive(Debug)]
pub struct CancellationToken<T> {
    sender: WatchSender<Option<T>>,
    receiver: WatchReceiver<Option<T>>,
}

impl<T> CancellationToken<T> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_cancelled(&self) -> bool {
        self.receiver.borrow().is_some()
    }

    /// Cancels the token with the provided reason.
    ///
    /// If the token was already cancelled this has no effect. Otherwise any
    /// tasks waiting on [`Self::cancelled`] are woken up and will read the
    /// provided reason.
    pub fn cancel(&self, reason: T) {
        self.sender.send_if_modified(|existing| {
            if existing.is_some() {
                return false;
            }
            *existing = Some(reason);
            true
        });
    }

    /// Waits for some token to cancel, then returns the reason.
    pub async fn cancelled(&self) -> T
    where
        T: Clone,
    {
        let mut receiver = self.receiver.clone();
        let reason = receiver
            .wait_for(|x| x.is_some())
            .await
            .expect("self contains a sender so there won't ever be no senders");
        reason.as_ref().expect("waited for Some").clone()
    }
}

impl<T> Default for CancellationToken<T> {
    fn default() -> Self {
        let (sender, receiver) = tokio::sync::watch::channel(None);
        Self { sender, receiver }
    }
}

#[cfg(test)]
mod test {
    use std::future::Future as _;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use futures_util::{pin_mut, FutureExt};
    use test_case::test_case;

    use super::*;
    use crate::utils::testutil::TestWaker;

    #[test]
    fn cancel_is_visible() {
        let token = CancellationToken::new();
        let other_token = token.clone();

        assert!(!token.is_cancelled());
        assert_eq!(token.cancelled().now_or_never(), None);

        assert_eq!(other_token.cancelled().now_or_never(), None);
        assert!(!other_token.is_cancelled());

        token.cancel(());

        assert_eq!(token.cancelled().now_or_never(), Some(()));
        assert_eq!(other_token.cancelled().now_or_never(), Some(()));

        assert!(token.is_cancelled());
        assert!(other_token.is_cancelled());
    }

    #[test]
    fn cancel_before_clone_is_visible() {
        let token = CancellationToken::new();
        token.cancel(());

        let other_token = token.clone();

        assert_eq!(token.cancelled().now_or_never(), Some(()));
        assert_eq!(other_token.cancelled().now_or_never(), Some(()));

        assert!(token.is_cancelled());
        assert!(other_token.is_cancelled());
    }

    #[test_case(true; "same token")]
    #[test_case(false; "other token")]
    fn cancel_unblocks_cancelled_future(cancel_on_same_token: bool) {
        let token = CancellationToken::new();

        let waiting_future = token.cancelled();
        pin_mut!(waiting_future);

        let waker = Arc::new(TestWaker::default());
        let result = waiting_future
            .as_mut()
            .poll(&mut Context::from_waker(&waker.as_waker()));
        assert_eq!(result, Poll::Pending);
        assert!(!waker.was_woken());

        if cancel_on_same_token {
            token.cancel(());
        } else {
            token.clone().cancel(());
        }

        assert!(waker.was_woken());
        let result = waiting_future
            .as_mut()
            .poll(&mut Context::from_waker(&waker.as_waker()));
        assert_eq!(result, Poll::Ready(()));
    }

    #[test]
    fn first_cancel_wins() {
        let token = CancellationToken::new();
        token.cancel(1);
        token.cancel(2);
        token.cancel(3);

        assert_eq!(token.cancelled().now_or_never(), Some(1));
    }

    #[test]
    fn cancelled_is_idempotent() {
        let token = CancellationToken::new();
        token.cancel(());
        assert!(token.is_cancelled());

        assert_eq!(token.cancelled().now_or_never(), Some(()));

        assert_eq!(token.cancelled().now_or_never(), Some(()));
    }
}
