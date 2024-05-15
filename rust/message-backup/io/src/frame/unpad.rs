//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;
use std::pin::Pin;
use std::task::Poll;

use aes::cipher::BlockSizeUser;
use arrayvec::ArrayVec;
use cbc::cipher::block_padding::{Padding, UnpadError};
use cbc::cipher::Block;
use futures::{ready, Stream, StreamExt as _};

/// Stream wrapper that un-pads the last block.
///
/// Stream wrapper that wraps a stream of blocks. When the wrapped stream ends,
/// the last block is unpadded. If it is non-empty, it is yielded as the last
/// item from the stream.
#[derive(Debug)]
pub(crate) struct UnpadLast<S: Stream, P, B: BlockSizeUser, const N: usize> {
    maybe_stream: Option<S>,
    maybe_buffer: Option<Block<B>>,
    _marker: PhantomData<P>,
}

impl<S: Stream, P, B: BlockSizeUser, const N: usize> UnpadLast<S, P, B, N> {
    pub(crate) fn new(stream: S) -> Self {
        Self {
            maybe_stream: Some(stream),
            maybe_buffer: None,
            _marker: PhantomData,
        }
    }
}

impl<S, P, B, const N: usize> Stream for UnpadLast<S, P, B, N>
where
    S: Stream<Item = futures::io::Result<Block<B>>> + Unpin,
    P: Padding<B::BlockSize> + Unpin,
    B: BlockSizeUser,
    Block<B>: Unpin + Into<[u8; N]>,
{
    type Item = futures::io::Result<ArrayVec<u8, N>>;
    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self {
            maybe_stream,
            maybe_buffer,
            _marker,
        } = self.get_mut();

        let Some(stream) = maybe_stream else {
            return Poll::Ready(None);
        };

        let buffer = match maybe_buffer {
            None => {
                let Some(first_block) = ready!(stream.poll_next_unpin(cx)).transpose()? else {
                    return Poll::Ready(None);
                };
                maybe_buffer.insert(first_block)
            }
            Some(buffer) => buffer,
        };

        let output = match ready!(stream.poll_next_unpin(cx)).transpose()? {
            Some(block) => {
                let was_buffered = std::mem::replace(buffer, block);
                let array: [u8; N] = was_buffered.into();
                Some(array.into())
            }
            None => {
                *maybe_stream = None;
                let tail =
                    P::unpad(&*buffer).map_err(|UnpadError| futures::io::ErrorKind::InvalidData)?;

                if tail.is_empty() {
                    None
                } else {
                    Some(ArrayVec::from_iter(tail.iter().copied()))
                }
            }
        };
        Poll::Ready(Ok(output).transpose())
    }
}

#[cfg(test)]
mod test {
    use aes::cipher::typenum::U16;
    use array_concat::concat_arrays;
    use assert_matches::assert_matches;
    use cbc::cipher::block_padding::Pkcs7;
    use futures::executor::block_on;
    use futures::{FutureExt, StreamExt, TryStreamExt};

    use super::*;

    struct BlockSized;

    impl BlockSizeUser for BlockSized {
        type BlockSize = U16;
    }

    #[test]
    fn empty() {
        let mut stream = UnpadLast::<_, Pkcs7, BlockSized, 16>::new(futures::stream::empty());

        assert_matches!(stream.next().now_or_never(), Some(None));
    }
    const LAST: [u8; 10] = [0xab; 10];
    const LAST_PADDING: [u8; 6] = [6; 6];

    #[test]
    fn single() {
        let padded: [u8; 16] = concat_arrays!(LAST, LAST_PADDING);
        let stream =
            UnpadLast::<_, Pkcs7, BlockSized, 16>::new(futures::stream::iter([Ok(padded.into())]));

        let blocks: Vec<_> = block_on(stream.try_collect()).expect("no error");
        assert_eq!(&blocks, &[ArrayVec::from_iter(LAST)])
    }

    #[test]
    fn multiple() {
        let padded: [u8; 16] = concat_arrays!(LAST, LAST_PADDING);
        let stream = UnpadLast::<_, Pkcs7, BlockSized, 16>::new(futures::stream::iter(
            [[0x11; 16].into(), [0x22; 16].into(), padded.into()].map(Ok),
        ));

        let blocks: Vec<_> = block_on(stream.try_collect()).expect("no error");
        assert_eq!(
            &blocks,
            &[
                ArrayVec::from([0x11; 16]),
                ArrayVec::from([0x22; 16]),
                ArrayVec::from_iter(LAST)
            ]
        )
    }

    const ALL_PADDING: [u8; 16] = [16; 16];

    #[test]
    fn last_is_all_padding() {
        let stream = UnpadLast::<_, Pkcs7, BlockSized, 16>::new(futures::stream::iter(
            [[0x11; 16].into(), [0x22; 16].into(), ALL_PADDING.into()].map(Ok),
        ));

        let blocks: Vec<_> = block_on(stream.try_collect()).expect("no error");
        assert_eq!(
            &blocks,
            &[ArrayVec::from([0x11; 16]), ArrayVec::from([0x22; 16]),]
        )
    }

    #[test]
    fn empty_without_padding() {
        let stream = UnpadLast::<_, Pkcs7, BlockSized, 16>::new(futures::stream::iter([Ok(
            ALL_PADDING.into(),
        )]));

        let blocks: Vec<_> = block_on(stream.try_collect()).expect("no error");
        assert_eq!(blocks, Vec::<ArrayVec<u8, 16>>::new());
    }
}
