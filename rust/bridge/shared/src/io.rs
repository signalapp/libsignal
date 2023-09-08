//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::io;
use std::pin::Pin;

use async_trait::async_trait;

/// The result of a [`InputStream::read`].
///
/// This `enum` exists so that [`InputStream::read`] may be implemented as either a sync or async operation. In the
/// synchronous case, data is read directly into the buffer provided by the caller, to avoid the extra allocation and
/// data copy necessary in the async case.
#[must_use]
pub enum InputStreamRead<'a> {
    /// The read operation must be completed by awaiting a [`Future`] yielding the read bytes. The buffer provided to
    /// [`InputStream::read`] was not modified.
    Pending(Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + 'a>>),

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
