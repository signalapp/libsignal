//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures_util::future::LocalBoxFuture;
use futures_util::{AsyncRead, FutureExt as _};
use mediasan_common::{AsyncSkip, Skip};

/// The result of a [`InputStream::read`].
///
/// This `enum` exists so that [`InputStream::read`] may be implemented as either a sync or async operation. In the
/// synchronous case, data is read directly into the buffer provided by the caller, to avoid the extra allocation and
/// data copy necessary in the async case.
#[must_use]
pub enum InputStreamRead<'a> {
    /// The read operation must be completed by awaiting a [`Future`] yielding the read bytes. The buffer provided to
    /// [`InputStream::read`] was not modified.
    ///
    /// [`Future`]: std::future::Future
    Pending(LocalBoxFuture<'a, io::Result<Vec<u8>>>),

    /// The read operation completed immediately, and `amount_read` bytes were copied into the buffer provided to
    /// [`InputStream::read`].
    Ready { amount_read: usize },
}

/// An input stream of bytes.
#[async_trait(?Send)]
pub trait InputStream {
    /// Read an amount of bytes from the input stream.
    ///
    /// The actual amount of bytes returned may be smaller than the buffer provided by the caller, for any reason;
    /// however, reading zero bytes always indicates that the end of the stream has been reached.
    ///
    /// # Returns
    ///
    /// An [`InputStreamRead`] indicating whether the read was completed as a sync or async operation. In the
    /// synchronous case, data is read directly into the buffer provided by the caller, to avoid the extra allocation
    /// and data copy necessary in the async case.
    ///
    /// # Errors
    ///
    /// If an I/O error occurred while reading from the input, an [`io::Error`] is returned.
    fn read<'out, 'a: 'out>(&'a self, buf: &mut [u8]) -> io::Result<InputStreamRead<'out>>
    where
        Self: 'out;

    /// Skip an amount of bytes in the input stream.
    ///
    /// # Errors
    ///
    /// If the requested number of bytes could not be skipped for any reason, including if the end of stream was
    /// reached, an error must be returned.
    async fn skip(&self, amount: u64) -> io::Result<()>;
}

/// An input stream of bytes.
pub trait SyncInputStream {
    /// Read an amount of bytes from the input stream.
    ///
    /// The actual amount of bytes returned may be smaller than the buffer provided by the caller, for any reason;
    /// however, reading zero bytes always indicates that the end of the stream has been reached.
    ///
    /// # Returns
    ///
    /// The number of bytes read and copied into the provided buffer `buf`.
    ///
    /// # Errors
    ///
    /// If an I/O error occurred while reading from the input, an [`io::Error`] is returned.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Skip an amount of bytes in the input stream.
    ///
    /// # Errors
    ///
    /// If the requested number of bytes could not be skipped for any reason, including if the end of stream was
    /// reached, an error must be returned.
    fn skip(&self, amount: u64) -> io::Result<()>;
}

pub struct SyncInput<'a> {
    stream: &'a dyn SyncInputStream,
    pos: u64,
    len: Option<u64>,
}

impl<'a> SyncInput<'a> {
    pub fn new(stream: &'a dyn SyncInputStream, len: Option<u64>) -> Self {
        Self {
            stream,
            len,
            pos: 0,
        }
    }
}

pub struct AsyncInput<'a> {
    stream: &'a dyn InputStream,
    state: AsyncInputState<'a>,
    pos: u64,
    len: u64,
}

impl<'a> AsyncInput<'a> {
    pub fn new(stream: &'a dyn InputStream, len: u64) -> Self {
        Self {
            stream,
            state: AsyncInputState::default(),
            pos: 0,
            len,
        }
    }
}

#[derive(Default)]
enum AsyncInputState<'a> {
    #[default]
    Idle,
    Reading(LocalBoxFuture<'a, io::Result<Vec<u8>>>),
    Skipping(LocalBoxFuture<'a, io::Result<()>>),
}

impl std::io::Read for SyncInput<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let amount_read = self.stream.read(buf)?;
        let new_pos = self.pos.checked_add(amount_read as u64);
        self.pos = new_pos
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "input length overflow"))?;
        Ok(amount_read)
    }
}

impl Skip for SyncInput<'_> {
    fn skip(&mut self, amount: u64) -> io::Result<()> {
        self.stream.skip(amount)?;
        self.pos = self
            .pos
            .checked_add(amount)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "input length overflow"))?;
        Ok(())
    }

    fn stream_position(&mut self) -> io::Result<u64> {
        Ok(self.pos)
    }

    fn stream_len(&mut self) -> io::Result<u64> {
        Ok(self.len.expect("stream length provided for this input"))
    }
}

impl AsyncRead for AsyncInput<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let input_stream_read = match std::mem::take(&mut self.state) {
            AsyncInputState::Idle => self.stream.read(buf)?,
            AsyncInputState::Reading(read_future) => InputStreamRead::Pending(read_future),
            AsyncInputState::Skipping { .. } => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot read while skipping",
                )))
            }
        };

        let amount_read = match input_stream_read {
            InputStreamRead::Pending(mut read_future) => match read_future.poll_unpin(cx) {
                Poll::Ready(Ok(data)) => {
                    buf[..data.len()].copy_from_slice(&data[..]);
                    data.len()
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => {
                    self.state = AsyncInputState::Reading(read_future);
                    return Poll::Pending;
                }
            },
            InputStreamRead::Ready { amount_read } => amount_read,
        };

        let new_pos = self.pos.checked_add(amount_read as u64);
        self.pos = new_pos
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "input length overflow"))?;

        Poll::Ready(Ok(amount_read))
    }
}

impl AsyncSkip for AsyncInput<'_> {
    fn poll_skip(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        amount: u64,
    ) -> Poll<io::Result<()>> {
        let mut skip_future = match std::mem::take(&mut self.state) {
            AsyncInputState::Idle => self.stream.skip(amount),
            AsyncInputState::Skipping(skip_future) => skip_future,
            AsyncInputState::Reading { .. } => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::Other,
                    "cannot skip while reading",
                )))
            }
        };
        match skip_future.poll_unpin(cx) {
            Poll::Ready(Ok(())) => {
                self.pos = self.pos.checked_add(amount).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "input length overflow")
                })?;

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => {
                self.state = AsyncInputState::Skipping(skip_future);
                Poll::Pending
            }
        }
    }

    fn poll_stream_position(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self.pos))
    }

    fn poll_stream_len(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<u64>> {
        Poll::Ready(Ok(self.len))
    }
}
