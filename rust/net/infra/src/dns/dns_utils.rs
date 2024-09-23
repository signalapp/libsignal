//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::time::Duration;

const SIGNAL_DOMAIN_SUFFIX: &str = ".signal.org";

/// Tries to get at least one, and possibly two `Ok(_)` results from the given futures,
/// if they complete successfully within a `delay` interval from each other.
///
/// Given two futures that return `Result<T1/T2, E>`, this function tries to drive both of them
/// to completion. If any one completes with `Ok(res)`, then the other one is given `delay` time
/// to finish, too. If any future completes with an `Err(_)`, the error is dropped
/// and the `delay` timer is not activated for the remaining future.
/// Depending on the timing and results of the futures,
/// this function may return any combination of `(Some(r1)/None, Some(r2)/None)`.
pub(crate) async fn results_within_interval<T1, T2, E1, E2, F1, F2>(
    future_1: F1,
    future_2: F2,
    delay: Duration,
) -> (Option<T1>, Option<T2>)
where
    F1: Future<Output = Result<T1, E1>>,
    F2: Future<Output = Result<T2, E2>>,
{
    tokio::pin!(future_1, future_2);
    tokio::select! {
        res_1 = &mut future_1 => match res_1 {
            Ok(ok_1) => (Some(ok_1), ok_with_timeout(future_2, delay).await),
            Err(_) => (None, future_2.await.ok()),
        },
        res_2 = &mut future_2 => match res_2 {
            Ok(ok_2) => (ok_with_timeout(future_1, delay).await, Some(ok_2)),
            Err(_) => (future_1.await.ok(), None),
        },
    }
}

/// A helper function that takes in a future that produces a `Result<T, E>` and a `delay` interval
/// and that returns `Some(res)` if the future completes with `Ok(res)` within the given timeframe.
pub(crate) async fn ok_with_timeout<T, E, F>(future: F, delay: Duration) -> Option<T>
where
    F: Future<Output = Result<T, E>>,
{
    match tokio::time::timeout(delay, future).await {
        Ok(res) => res.ok(),
        Err(_) => None,
    }
}

pub(crate) fn log_safe_domain(domain: &str) -> &str {
    if domain.ends_with(SIGNAL_DOMAIN_SUFFIX) {
        domain
    } else {
        "REDACTED"
    }
}

pub mod oneshot_broadcast {
    use tokio::sync::watch;

    #[derive(Debug)]
    pub struct RecvError;

    #[derive(Debug)]
    pub struct SendError<T>(pub T);

    #[derive(Clone)]
    pub struct Receiver<T> {
        inner: watch::Receiver<Option<T>>,
    }

    impl<T: Clone> Receiver<T> {
        pub async fn val(&mut self) -> Result<T, RecvError> {
            let some_value = self
                .inner
                .wait_for(|val| val.is_some())
                .await
                .map_err(|_| RecvError)?;
            Ok(some_value
                .as_ref()
                .expect("None values filtered out")
                .clone())
        }
    }

    pub struct Sender<T> {
        inner: watch::Sender<Option<T>>,
    }

    impl<T> Sender<T> {
        pub fn send(self, val: T) -> Result<(), SendError<T>> {
            match self.inner.send(Some(val)) {
                Ok(_) => Ok(()),
                Err(watch::error::SendError(Some(v))) => Err(SendError(v)),
                Err(watch::error::SendError(None)) => unreachable!("Only Some(_) values are sent"),
            }
        }
    }

    pub fn channel<T: Clone>() -> (Sender<T>, Receiver<T>) {
        let (tx, rx) = watch::channel::<Option<T>>(None);
        (Sender { inner: tx }, Receiver { inner: rx })
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;

    use super::oneshot_broadcast::SendError;
    use super::*;

    #[tokio::test]
    async fn oneshot_broadcast_completes_for_multiple_receivers() {
        let (tx, mut rx) = oneshot_broadcast::channel::<i32>();

        let mut rx_clone = rx.clone();
        let join = tokio::spawn(async move { rx_clone.val().await });

        tx.send(42).unwrap();

        assert_eq!(42, rx.val().await.unwrap());
        assert_eq!(42, join.await.unwrap().unwrap());
    }

    #[tokio::test]
    async fn oneshot_broadcast_can_be_used_multiple_times() {
        let (tx, mut rx) = oneshot_broadcast::channel::<i32>();

        tx.send(42).unwrap();

        assert_eq!(42, rx.val().await.unwrap());
        assert_eq!(42, rx.val().await.unwrap());
    }

    #[tokio::test]
    async fn oneshot_broadcast_completes_receiver_cloned_after_completion() {
        let (tx, mut rx) = oneshot_broadcast::channel::<i32>();
        tx.send(42).unwrap();
        assert_eq!(42, rx.val().await.unwrap());
        assert_eq!(42, rx.clone().val().await.unwrap());
    }

    #[tokio::test]
    async fn oneshot_broadcast_sender_error_if_no_receivers() {
        let (tx, rx) = oneshot_broadcast::channel::<i32>();
        drop(rx);
        assert_matches!(tx.send(42), Err(SendError(42)));
    }

    #[tokio::test]
    async fn oneshot_broadcast_receiver_error_if_sender_dropped() {
        let (tx, mut rx) = oneshot_broadcast::channel::<i32>();
        drop(tx);
        assert_matches!(rx.val().await, Err(oneshot_broadcast::RecvError));
    }
}
