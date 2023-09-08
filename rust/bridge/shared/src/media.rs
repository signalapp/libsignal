//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io;
use std::mem::take;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::future::LocalBoxFuture;
use futures_util::AsyncRead;
use libsignal_bridge_macros::*;
use signal_media::sanitize::{sanitize_mp4, AsyncSkip, Error, SanitizedMetadata};

use crate::io::{InputStream, InputStreamRead};

// Not used by the Java bridge.
#[allow(unused_imports)]
use crate::support::*;
use crate::*;

// Will be unused when building for Node only.
#[allow(unused_imports)]
use futures_util::FutureExt;

struct SanitizerInput<'a> {
    stream: &'a dyn InputStream,
    state: SanitizerInputState<'a>,
    pos: u64,
    len: u64,
}

#[derive(Default)]
enum SanitizerInputState<'a> {
    #[default]
    Idle,
    Reading(LocalBoxFuture<'a, io::Result<Vec<u8>>>),
    Skipping(LocalBoxFuture<'a, io::Result<()>>),
}

/// Exposed so that we have an easy method to invoke from Java to test whether libsignal was
/// compiled with signal-media.
#[bridge_fn]
fn SignalMedia_CheckAvailable() {}

#[bridge_fn]
async fn Mp4Sanitizer_Sanitize(
    input: &mut dyn InputStream,
    len: u64,
) -> Result<SanitizedMetadata, Error> {
    let input = SanitizerInput {
        stream: input,
        state: Default::default(),
        pos: 0,
        len,
    };
    let metadata = sanitize_mp4(input).await?;
    Ok(metadata)
}

bridge_handle!(SanitizedMetadata);

#[bridge_fn]
fn SanitizedMetadata_GetMetadata(sanitized: &SanitizedMetadata) -> &[u8] {
    sanitized.metadata.as_deref().unwrap_or_default()
}

#[bridge_fn]
fn SanitizedMetadata_GetDataOffset(sanitized: &SanitizedMetadata) -> u64 {
    sanitized.data.offset
}

#[bridge_fn]
fn SanitizedMetadata_GetDataLen(sanitized: &SanitizedMetadata) -> u64 {
    sanitized.data.len
}

impl AsyncRead for SanitizerInput<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let input_stream_read = match take(&mut self.state) {
            SanitizerInputState::Idle => self.stream.read(buf)?,
            SanitizerInputState::Reading(read_future) => InputStreamRead::Pending(read_future),
            SanitizerInputState::Skipping { .. } => {
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
                    self.state = SanitizerInputState::Reading(read_future);
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

impl AsyncSkip for SanitizerInput<'_> {
    fn poll_skip(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        amount: u64,
    ) -> Poll<io::Result<()>> {
        let mut skip_future = match take(&mut self.state) {
            SanitizerInputState::Idle => self.stream.skip(amount),
            SanitizerInputState::Skipping(skip_future) => skip_future,
            SanitizerInputState::Reading { .. } => {
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
                self.state = SanitizerInputState::Skipping(skip_future);
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
