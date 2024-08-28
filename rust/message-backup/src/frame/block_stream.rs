//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::array::TryFromSliceError;
use std::pin::Pin;
use std::task::Poll;

use arrayvec::ArrayVec;
use futures::{ready, AsyncRead, Stream, StreamExt};

/// Adapter that reads blocks into a stream.
///
/// Reads bytes from a [`futures::io::AsyncRead`] implementation into blocks of
/// size at most `N` and makes those available via a [`futures::Stream`]
/// implementation.
///
/// All but the final block is guaranteed to have `N` bytes.
#[derive(Debug)]
pub(crate) struct BlockStream<const N: usize, R> {
    next_bytes: [u8; N],
    next_read: usize,
    reader: Option<R>,
}

impl<R: AsyncRead + Unpin, const N: usize> BlockStream<N, R> {
    pub(crate) fn new(reader: R) -> Self {
        Self {
            next_bytes: [0; N],
            next_read: 0,
            reader: Some(reader),
        }
    }
}

impl<R: AsyncRead + Unpin, const N: usize> Stream for BlockStream<N, R> {
    type Item = futures::io::Result<ArrayVec<u8, N>>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            next_bytes,
            next_read,
            reader: maybe_reader,
        } = self.get_mut();

        let Some(reader) = maybe_reader.as_mut() else {
            return Poll::Ready(None);
        };

        assert_ne!(*next_read, next_bytes.len());

        while *next_read != next_bytes.len() {
            let count =
                ready!(Pin::new(&mut *reader).poll_read(cx, &mut next_bytes[*next_read..])?);
            if count == 0 {
                break;
            }
            *next_read += count;
        }

        let block = std::mem::replace(next_bytes, [0; N]);
        if *next_read == next_bytes.len() {
            *next_read = 0;
            Poll::Ready(Some(Ok(block.into())))
        } else {
            *maybe_reader = None;
            Poll::Ready(if *next_read == 0 {
                None
            } else {
                Some(Ok(block[..*next_read]
                    .try_into()
                    .expect("always less than the full capacity")))
            })
        }
    }
}

/// Adapter that reads fixed-sized blocks as a [`futures::Stream`].
///
/// If the reader finishes after produces a number of bytes not divisible by the
/// block size, an [`UnexpectedEof`](futures::io::ErrorKind::UnexpectedEof)
/// error is yielded.
#[derive(Debug)]
pub(crate) struct ExactBlockStream<const N: usize, S> {
    inner: S,
}

impl<S, const N: usize> ExactBlockStream<N, S> {
    pub(crate) fn new(stream: S) -> Self {
        Self { inner: stream }
    }
}

impl<
        S: Stream<Item = Result<ArrayVec<u8, N>, E>> + Unpin,
        E: Into<futures::io::Error>,
        const N: usize,
    > Stream for ExactBlockStream<N, S>
{
    type Item = futures::io::Result<[u8; N]>;
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Some(block) = ready!(self.get_mut().inner.poll_next_unpin(cx).map_err(E::into)?) else {
            return Poll::Ready(None);
        };

        Poll::Ready(Some(block.as_ref().try_into().map_err(
            |_: TryFromSliceError| futures::io::ErrorKind::UnexpectedEof.into(),
        )))
    }
}

/// [`ExactBlockStream`] that pulls from an [`AsyncRead`]er.
pub(crate) type ExactReadBlockStream<const N: usize, R> = ExactBlockStream<N, BlockStream<N, R>>;

impl<R: AsyncRead + Unpin, const N: usize> ExactReadBlockStream<N, R> {
    pub(crate) fn from_reader(reader: R) -> Self {
        Self::new(BlockStream::new(reader))
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use futures::executor::block_on;
    use futures::{FutureExt, StreamExt, TryStreamExt as _};

    use super::*;

    #[test]
    fn empty() {
        let mut stream = BlockStream::<10, _>::new([].as_slice());
        assert_matches!(stream.next().now_or_never(), Some(None));
    }

    #[test]
    fn multiple_blocks() {
        let stream = BlockStream::<2, _>::new(b"aabbccd".as_slice());
        let contents: Vec<_> = block_on(stream.try_collect()).expect("no error");
        assert_eq!(
            &contents,
            &[
                ArrayVec::from(*b"aa"),
                ArrayVec::from(*b"bb"),
                ArrayVec::from(*b"cc"),
                ArrayVec::from_iter(*b"d"),
            ]
        );
    }

    #[test]
    fn reader_returns_pending() {
        let (sender, receiver) = futures::channel::mpsc::unbounded::<Result<Vec<u8>, _>>();
        let mut stream = BlockStream::<2, _>::new(receiver.into_async_read());

        sender
            .unbounded_send(Ok(Vec::from(*b"abc")))
            .expect("can send");

        assert_eq!(
            stream
                .next()
                .now_or_never()
                .flatten()
                .transpose()
                .expect("no error")
                .expect("has block"),
            ArrayVec::from(*b"ab")
        );

        // The input reader doesn't have more data for this next poll.
        assert_matches!(stream.next().now_or_never(), None);

        // Send two more bytes then end the input.
        sender
            .unbounded_send(Ok(Vec::from(*b"de")))
            .expect("can send");
        drop(sender);

        assert_eq!(
            stream
                .next()
                .now_or_never()
                .flatten()
                .transpose()
                .expect("no error")
                .expect("has block"),
            ArrayVec::from(*b"cd")
        );

        assert_eq!(
            stream
                .next()
                .now_or_never()
                .flatten()
                .transpose()
                .expect("no error")
                .expect("has block"),
            ArrayVec::from_iter(*b"e")
        );
        assert_matches!(stream.next().now_or_never(), Some(None));
    }

    #[test]
    fn reader_returns_error() {
        let (sender, receiver) = futures::channel::mpsc::unbounded::<Result<Vec<u8>, _>>();
        let mut stream = BlockStream::<2, _>::new(receiver.into_async_read());

        sender
            .unbounded_send(Ok(Vec::from(*b"abc")))
            .expect("can send");

        assert_matches!(stream.next().now_or_never(), Some(Some(Ok(_))));

        // An error from the reader should be bubbled up.
        sender
            .unbounded_send(Err(futures::io::Error::new(
                futures::io::ErrorKind::Other,
                "unknown error",
            )))
            .expect("can send");

        assert_matches!(
            stream.next().now_or_never(),
            Some(Some(Err(e))) if e.kind() == futures::io::ErrorKind::Other
        );
    }

    #[test]
    fn exact_block_stream_valid() {
        use futures::io::Error;
        const BLOCKS: [[u8; 2]; 3] = [*b"ab", *b"cd", *b"ef"];

        let input = futures::stream::iter(BLOCKS.map(|b| Ok::<_, Error>(ArrayVec::from(b))));
        let stream = ExactBlockStream::new(input);
        let output: Vec<[u8; 2]> = block_on(stream.try_collect()).expect("no error");
        assert_eq!(&output[..], BLOCKS);
    }

    #[test]
    fn exact_block_stream_ragged_block() {
        let (sender, receiver) = futures::channel::mpsc::unbounded::<futures::io::Result<_>>();
        let mut stream = ExactBlockStream::new(receiver);

        assert_matches!(stream.next().now_or_never(), None);

        sender
            .unbounded_send(Ok(ArrayVec::from(*b"ab")))
            .expect("can send");
        assert_matches!(stream.next().now_or_never(), Some(Some(Ok(b))) if b == *b"ab");

        sender
            .unbounded_send(Ok(ArrayVec::new()))
            .expect("can send");
        assert_matches!(stream.next().now_or_never(), Some(Some(Err(e))) if e.kind() == futures::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn exact_block_stream_converts_error() {
        struct IntoIoError;

        impl From<IntoIoError> for futures::io::Error {
            fn from(IntoIoError: IntoIoError) -> Self {
                futures::io::Error::new(futures::io::ErrorKind::Other, "into io error")
            }
        }

        let (sender, receiver) = futures::channel::mpsc::unbounded::<Result<ArrayVec<u8, 2>, _>>();
        let mut stream = ExactBlockStream::new(receiver);
        assert_matches!(stream.next().now_or_never(), None);

        sender.unbounded_send(Err(IntoIoError)).expect("can send");
        assert_matches!(stream.next().now_or_never(), Some(Some(Err(e))) if e.kind() == futures::io::ErrorKind::Other);
    }
}
