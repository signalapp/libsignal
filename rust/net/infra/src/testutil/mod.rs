//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::io::Error as IoError;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use displaydoc::Display;
use futures_util::stream::FusedStream;
use futures_util::{Sink, SinkExt as _, Stream};
use tokio_util::sync::PollSender;

use crate::errors::LogSafeDisplay;

pub mod fake_transport;

#[derive(Debug, Display)]
pub enum TestError {
    /// expected error
    Expected,
    /// unexpected error
    Unexpected(&'static str),
}

impl LogSafeDisplay for TestError {}

// This could be Copy, but we don't want to rely on *all* errors being Copy, or only test
// that case.

// the choice of the constant value is dictated by a vague notion of being
// "not too many, but also not just once or twice"

pub const TIMEOUT_DURATION: Duration = Duration::from_millis(1000);

// we need to advance time in tests by some value not to run into the scenario
// of attempts starting at the same time, but also by not too much so that we
// don't step over the cool down time

/// Trivial [`Sink`] and [`Stream`] implementation over a pair of buffered channels.
#[derive(Debug)]
pub struct TestStream<T, E> {
    rx: tokio::sync::mpsc::Receiver<Result<T, E>>,
    tx: PollSender<Result<T, E>>,
}

impl<T: Send, E: Send> TestStream<T, E> {
    pub fn new_pair(channel_size: usize) -> (Self, Self) {
        let [lch, rch] = [(); 2].map(|()| tokio::sync::mpsc::channel(channel_size));
        let l = Self {
            rx: lch.1,
            tx: PollSender::new(rch.0),
        };
        let r = Self {
            rx: rch.1,
            tx: PollSender::new(lch.0),
        };
        (l, r)
    }

    pub async fn send_error(&mut self, error: E) -> Result<(), Option<E>> {
        self.tx.send(Err(error)).await.map_err(|e| {
            e.into_inner().map(|r| match r {
                Ok(_) => unreachable!("sent item was an error"),
                Err(e) => e,
            })
        })
    }
    pub fn rx_is_closed(&self) -> bool {
        self.rx.is_closed()
    }
}

impl<T: Send, E: Send> Stream for TestStream<T, E> {
    type Item = Result<T, E>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.get_mut().rx.poll_recv(cx)
    }
}

impl<T: Send, E: Send> FusedStream for TestStream<T, E> {
    fn is_terminated(&self) -> bool {
        self.rx.is_closed() && self.rx.is_empty()
    }
}

impl<T: Send, E: Send + From<IoError>> Sink<T> for TestStream<T, E> {
    type Error = E;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut()
            .tx
            .poll_ready_unpin(cx)
            .map_err(|_| IoError::other("poll_reserve for send failed").into())
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        self.get_mut()
            .tx
            .start_send_unpin(Ok(item))
            .map_err(|_| IoError::other("send failed").into())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut()
            .tx
            .poll_flush_unpin(cx)
            .map_err(|_| IoError::other("flush failed").into())
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut()
            .tx
            .poll_close_unpin(cx)
            .map_err(|_| IoError::other("close failed").into())
    }
}
