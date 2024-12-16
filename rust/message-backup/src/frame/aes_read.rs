//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cell::RefCell;
use std::pin::Pin;
use std::rc::Rc;
use std::task::Poll;

use aes::Aes256;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::generic_array::GenericArray;
use cbc::cipher::{BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, Unsigned};
use futures::{AsyncRead, TryStreamExt};

use crate::frame::block_stream::ExactReadBlockStream;
use crate::frame::cbc::CbcStreamDecryptor;
use crate::frame::unpad::UnpadLast;

const AES_BLOCK_SIZE: usize = <<Aes256 as BlockSizeUser>::BlockSize as Unsigned>::USIZE;
pub const AES_KEY_SIZE: usize = <<Aes256 as KeySizeUser>::KeySize as Unsigned>::USIZE;
pub const AES_IV_SIZE: usize = <<cbc::Decryptor<Aes256> as IvSizeUser>::IvSize as Unsigned>::USIZE;

/// Decrypting implementation of [`futures::io::AsyncRead`].
///
/// Decrypts a stream of bytes that was encrypted with AES256-CBC with PKCS7
/// padding.
///
/// This exists as a named type to allow it to be held as a field in other types.
#[derive(Debug)]
pub struct Aes256CbcReader<R: AsyncRead + Unpin> {
    /// Reader for the bytes being produced.
    ///
    /// Bytes are pulled from the wrapped `R` reader, chunked into blocks which
    /// are fed into an [`Aes256`] decryptor as a stream, then un-padded and
    /// un-chunked in response to an [`AsyncRead::poll_read`] call.
    reader: futures::stream::IntoAsyncRead<
        Aes256CbcUnpadLast<Aes256CbcDecryptStream<BlockStream<RcReader<R>>>>,
    >,
    /// Separate reference to the wrapped reader for production via
    /// [`Aes256CbcReader::into_inner`].
    inner: Rc<RefCell<R>>,
}

impl<R: AsyncRead + Unpin> Aes256CbcReader<R> {
    pub fn new(key: &[u8; AES_KEY_SIZE], iv: &[u8; AES_IV_SIZE], reader: R) -> Self {
        let rc_reader = Rc::new(RefCell::new(reader));
        let reader = RcReader(rc_reader.clone());
        let stream: BlockStream<_> = ExactReadBlockStream::from_reader(reader).map_ok(Into::into);
        let decrypt: Aes256CbcDecryptStream<BlockStream<_>> =
            CbcStreamDecryptor::new(cbc::Decryptor::<Aes256>::new(key.into(), iv.into()), stream);
        let unpad = UnpadLast::<_, Pkcs7, _, 16>::new(decrypt);
        Self {
            reader: TryStreamExt::into_async_read(unpad),
            inner: rc_reader,
        }
    }

    /// Consumes the reader and returns the wrapped `R` reader.
    ///
    /// If this reader is exhaused (a call to [`AsyncRead::poll_read`] returned
    /// `Poll::Ready(Ok(0))`), then the returned reader is also exhausted.
    /// Otherwise no guarantees are made about the returned value.
    pub fn into_inner(self) -> R {
        let Self { reader, inner } = self;
        drop(reader);

        RefCell::into_inner(Rc::into_inner(inner).expect("only other reference was just dropped"))
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Aes256CbcReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<futures::io::Result<usize>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

/// A [`futures::Stream`] that yields decrypted and unpadded blocks.
type Aes256CbcUnpadLast<S> =
    UnpadLast<S, Pkcs7, Aes256, { <<Aes256 as BlockSizeUser>::BlockSize as Unsigned>::USIZE }>;

/// A [`futures::Stream`] that yields decrypted blocks.
///
/// The final block yielded will still have padding.
type BlockStream<R> = futures::prelude::stream::MapOk<
    ExactReadBlockStream<AES_BLOCK_SIZE, R>,
    fn([u8; AES_BLOCK_SIZE]) -> GenericArray<u8, <Aes256 as BlockSizeUser>::BlockSize>,
>;

/// A [`futures::Stream`] that decrypts individual blocks using AES256-CBC.
type Aes256CbcDecryptStream<S> = CbcStreamDecryptor<Aes256, S>;

/// A [`AsyncRead`]er that reads from shared mutable state.
///
/// Trivial implementer of `AsyncRead` around a `Rc<RefCell<R>>`.
#[derive(Debug)]
struct RcReader<R>(Rc<RefCell<R>>);

impl<R: AsyncRead + Unpin> AsyncRead for RcReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut *self.get_mut().0.borrow_mut()).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod test {
    use std::task::ready;

    use aes::Aes256;
    use assert_matches::assert_matches;
    use cbc::cipher::block_padding::Pkcs7;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use futures::executor::block_on;
    use futures::io::{AsyncReadExt, Cursor, ErrorKind};
    use futures::{pin_mut, FutureExt, TryStreamExt};
    use test_case::test_case;

    use super::*;

    const FAKE_KEY: [u8; AES_KEY_SIZE] = [0xaf; 32];
    const FAKE_IV: [u8; AES_IV_SIZE] = [0xbb; 16];

    #[test_case(&[]; "empty")]
    #[test_case(b"abcdefghijklmnopqrstuvwxyz"; "short")]
    #[test_case(&[0xab; 256]; "med")]
    #[test_case(&(0..=255).cycle().take(1024).collect::<Vec<u8>>(); "long")]
    fn aes_reader_round_trip(plaintext: &[u8]) {
        let encrypted = cbc::Encryptor::<Aes256>::new((&FAKE_KEY).into(), (&FAKE_IV).into())
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

        let mut reader = Aes256CbcReader::new(&FAKE_KEY, &FAKE_IV, encrypted.as_slice());
        let mut decrypted = Vec::new();
        block_on(reader.read_to_end(&mut decrypted)).expect("can read");

        assert_eq!(decrypted, plaintext)
    }

    fn aes_encrypted_bytes(plaintext: &[u8]) -> Vec<u8> {
        let ciphertext = cbc::Encryptor::<Aes256>::new((&FAKE_KEY).into(), (&FAKE_IV).into())
            .encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        assert_eq!(
            ciphertext.len(),
            plaintext.len().div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE
        );
        ciphertext
    }

    #[test]
    fn aes_reader_inner_returns_pending() {
        let (sender, receiver) = futures::channel::mpsc::unbounded::<Result<Vec<u8>, _>>();
        let mut reader = Aes256CbcReader::new(&FAKE_KEY, &FAKE_IV, receiver.into_async_read());

        const PLAINTEXT: [u8; 2 * AES_BLOCK_SIZE + 2] = *b"Supercalifragilisticexpialidocious";
        let ciphertext = aes_encrypted_bytes(&PLAINTEXT);
        assert_eq!(ciphertext.len(), AES_BLOCK_SIZE * 3);

        let mut to_send = ciphertext.as_slice();
        let mut received = Vec::new();

        let mut send_n_bytes = |n| {
            let mut to_read = vec![0; n];
            std::io::Read::read_exact(&mut to_send, &mut to_read).expect("enough bytes");
            sender.unbounded_send(Ok(to_read)).expect("reader exists");
            println!(
                "sender has received {} total bytes",
                ciphertext.len() - to_send.len()
            )
        };

        let mut try_read = || {
            let mut buf = [0; AES_BLOCK_SIZE * 2];
            let r = reader.read(&mut buf).now_or_never();
            if let Some(Ok(n)) = r {
                received.extend_from_slice(&buf[..n]);
            }
            assert_eq!(&received, &PLAINTEXT[..received.len()]);
            r
        };

        // There's nothing in the stream but the sender is still live so there
        // isn't anything to read yet.
        assert_matches!(try_read(), None);

        // Put less than a block of data in the stream. The reader still won't be able to read.
        send_n_bytes(AES_BLOCK_SIZE - 1);
        assert_matches!(try_read(), None);

        // Putting another byte in means the reader has a full block but doesn't
        // know if it's the last block, so it won't emit the block.
        send_n_bytes(1);
        assert_matches!(try_read(), None);

        // Send the reader more than a full block's worth of bytes. This will span two AES
        // blocks. Now the reader can emit the first block
        send_n_bytes(AES_BLOCK_SIZE + 1);
        assert_matches!(try_read(), Some(Ok(AES_BLOCK_SIZE)));

        // Send the bytes for the remaining block. Now block two is available.
        // The rest of the decrypted contents won't be available until the
        // stream is ended, though.
        send_n_bytes(AES_BLOCK_SIZE - 1);
        assert_matches!(try_read(), Some(Ok(AES_BLOCK_SIZE)));

        // Dropping the sender will end the stream and make the last block available.
        drop(sender);
        assert_matches!(try_read(), Some(Ok(2)));
    }

    #[test]
    fn aes_reader_too_short() {
        const SHORT_CONTENTS: [u8; 10] = *b"0123456789";
        let reader = Aes256CbcReader::new(&FAKE_KEY, &FAKE_IV, Cursor::new(SHORT_CONTENTS));
        pin_mut!(reader);

        let mut buf = [0; AES_BLOCK_SIZE * 2];
        assert_matches!(
            reader.read(&mut buf).now_or_never(),
            Some(Err(e)) if e.kind() == ErrorKind::UnexpectedEof);
    }

    struct CountingReader<R> {
        reader: R,
        bytes: usize,
    }

    impl<R> CountingReader<R> {
        fn new(reader: R) -> Self {
            Self { reader, bytes: 0 }
        }
    }

    impl<R: AsyncRead + Unpin> AsyncRead for CountingReader<R> {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            let Self { reader, bytes } = self.get_mut();
            let count = ready!(Pin::new(reader).poll_read(cx, buf))?;
            *bytes += count;

            Poll::Ready(Ok(count))
        }
    }

    #[test]
    fn into_inner() {
        let ciphertext = aes_encrypted_bytes(&[0; 34]);
        let ciphertext_len = ciphertext.len();
        let cursor_reader = Cursor::new(ciphertext);
        let mut reader =
            Aes256CbcReader::new(&FAKE_KEY, &FAKE_IV, CountingReader::new(cursor_reader));

        let mut out = vec![];
        let _ = reader
            .read_to_end(&mut out)
            .now_or_never()
            .expect("blocked unexpectedly")
            .expect("read successfully");

        let inner: CountingReader<_> = reader.into_inner();
        assert_eq!(inner.bytes, ciphertext_len)
    }
}
