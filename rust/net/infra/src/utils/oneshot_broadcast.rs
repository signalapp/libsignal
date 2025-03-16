//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

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

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;

    use super::*;

    #[tokio::test]
    async fn oneshot_broadcast_completes_for_multiple_receivers() {
        let (tx, mut rx) = super::channel::<i32>();

        let mut rx_clone = rx.clone();
        let join = tokio::spawn(async move { rx_clone.val().await });

        tx.send(42).unwrap();

        assert_eq!(42, rx.val().await.unwrap());
        assert_eq!(42, join.await.unwrap().unwrap());
    }

    #[tokio::test]
    async fn oneshot_broadcast_can_be_used_multiple_times() {
        let (tx, mut rx) = super::channel::<i32>();

        tx.send(42).unwrap();

        assert_eq!(42, rx.val().await.unwrap());
        assert_eq!(42, rx.val().await.unwrap());
    }

    #[tokio::test]
    async fn oneshot_broadcast_completes_receiver_cloned_after_completion() {
        let (tx, mut rx) = super::channel::<i32>();
        tx.send(42).unwrap();
        assert_eq!(42, rx.val().await.unwrap());
        assert_eq!(42, rx.clone().val().await.unwrap());
    }

    #[tokio::test]
    async fn oneshot_broadcast_sender_error_if_no_receivers() {
        let (tx, rx) = super::channel::<i32>();
        drop(rx);
        assert_matches!(tx.send(42), Err(SendError(42)));
    }

    #[tokio::test]
    async fn oneshot_broadcast_receiver_error_if_sender_dropped() {
        let (tx, mut rx) = super::channel::<i32>();
        drop(tx);
        assert_matches!(rx.val().await, Err(RecvError));
    }
}
