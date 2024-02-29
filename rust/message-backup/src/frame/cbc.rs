//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::pin::Pin;
use std::task::Poll;

use cbc::cipher::{Block, BlockCipher, BlockDecryptMut};
use derive_where::derive_where;
use futures::{ready, Stream, StreamExt as _};

/// Stream adapter that decrypts with a CBC stream cipher.
///
/// Wraps a [`futures::Stream`] that produces blocks and decrypts them using the
/// provided cipher.
#[derive_where(Debug; cbc::Decryptor<C>, S)]
pub(crate) struct CbcStreamDecryptor<C: BlockCipher + BlockDecryptMut, S> {
    decryptor: cbc::Decryptor<C>,
    source: S,
}

impl<S: Stream<Item = Result<Block<C>, E>>, E, C: BlockCipher + BlockDecryptMut>
    CbcStreamDecryptor<C, S>
{
    pub(crate) fn new(decryptor: cbc::Decryptor<C>, stream: S) -> Self {
        Self {
            decryptor,
            source: stream,
        }
    }
}

impl<S, C, E> Stream for CbcStreamDecryptor<C, S>
where
    S: Stream<Item = Result<Block<C>, E>> + Unpin,
    C: Unpin + BlockCipher + BlockDecryptMut,
    Block<C>: Unpin,
{
    type Item = Result<Block<C>, E>;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let Self { decryptor, source } = self.get_mut();

        let mut block = match ready!(source.poll_next_unpin(cx)).transpose()? {
            None => return Poll::Ready(None),
            Some(block) => block,
        };

        decryptor.decrypt_block_mut(&mut block);

        Poll::Ready(Some(Ok(block)))
    }
}

#[cfg(test)]
mod test {
    use aes::Aes256;
    use assert_matches::assert_matches;
    use cbc::cipher::generic_array::GenericArray;
    use cbc::cipher::{BlockEncryptMut, BlockSizeUser, KeyIvInit, Unsigned};
    use cbc::Decryptor;
    use futures::executor::block_on;
    use futures::{FutureExt as _, TryStreamExt};

    use super::*;

    const FAKE_AES_KEY: [u8; 32] = [0; 32];
    const FAKE_AES_ID: [u8; 16] = [0; 16];
    const AES_BLOCK_SIZE: usize = <<Aes256 as BlockSizeUser>::BlockSize as Unsigned>::USIZE;

    #[test]
    fn stream_empty() {
        let decryptor =
            Decryptor::<Aes256>::new(FAKE_AES_KEY.as_ref().into(), FAKE_AES_ID.as_ref().into());
        let mut stream = CbcStreamDecryptor::new(
            decryptor,
            futures::stream::empty::<futures::io::Result<Block<Aes256>>>(),
        );

        assert_matches!(stream.next().now_or_never(), Some(None));
    }

    #[test]
    fn stream_decrypts() {
        let decryptor = Decryptor::<Aes256>::new(&FAKE_AES_KEY.into(), &FAKE_AES_ID.into());
        const INPUT_BLOCKS: [[u8; AES_BLOCK_SIZE]; 2] = [[0xaa; 16], [0xbb; 16]];
        let encrypted: [[u8; AES_BLOCK_SIZE]; 2] = {
            let mut buf = INPUT_BLOCKS.map(Into::into);
            cbc::Encryptor::<Aes256>::new(&FAKE_AES_KEY.into(), &FAKE_AES_ID.into())
                .encrypt_blocks_mut(&mut buf);
            buf.map(Into::into)
        };

        let stream = CbcStreamDecryptor::new(
            decryptor,
            futures::stream::iter(encrypted)
                .map(GenericArray::from)
                .map(futures::io::Result::Ok),
        );

        let encrypted = block_on(
            stream
                .map_ok(<[u8; AES_BLOCK_SIZE]>::from)
                .try_collect::<Vec<[u8; AES_BLOCK_SIZE]>>(),
        )
        .expect("no error");
        assert_eq!(&encrypted, &INPUT_BLOCKS)
    }

    #[test]
    fn stream_passes_errors() {
        let decryptor = Decryptor::<Aes256>::new(&FAKE_AES_KEY.into(), &FAKE_AES_ID.into());

        let stream = CbcStreamDecryptor::new(
            decryptor,
            futures::stream::iter([
                Ok(GenericArray::from([0; AES_BLOCK_SIZE])),
                futures::io::Result::Err(futures::io::ErrorKind::UnexpectedEof.into()),
            ]),
        );

        assert_matches!(
            block_on(
                stream
                    .map_ok(<[u8; AES_BLOCK_SIZE]>::from)
                    .try_collect::<Vec<[u8; AES_BLOCK_SIZE]>>(),
            ),
            Err(e) if e.kind() == futures::io::ErrorKind::UnexpectedEof
        );
    }
}
