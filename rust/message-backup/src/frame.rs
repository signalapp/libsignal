//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::BorrowMut;

use aes::cipher::Unsigned;
use async_compression::futures::bufread::GzipDecoder;
use async_trait::async_trait;
use futures::io::{BufReader, Take};
use futures::{AsyncRead, AsyncReadExt};
use hmac::digest::OutputSizeUser;
use hmac::{Hmac, Mac as _};
use mediasan_common::{AsyncSkip, AsyncSkipExt as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

use crate::key::MessageBackupKey;

mod aes_read;
mod block_stream;
mod cbc;
mod mac_read;
mod reader_factory;
mod unpad;

#[cfg(feature = "test-util")]
pub use aes_read::AES_KEY_SIZE;
#[cfg_attr(feature = "test-util", visibility::make(pub))]
use aes_read::{Aes256CbcReader, AES_IV_SIZE};
#[cfg_attr(feature = "test-util", visibility::make(pub))]
use mac_read::MacReader;
pub use reader_factory::{CursorFactory, FileReaderFactory, LimitedReaderFactory, ReaderFactory};

const HMAC_LEN: usize = <<Hmac<Sha256> as OutputSizeUser>::OutputSize as Unsigned>::USIZE;

#[derive(Debug)]
pub struct FramesReader<R: AsyncRead + Unpin> {
    reader: GzipDecoder<BufReader<Aes256CbcReader<HmacSha256Reader<Take<R>>>>>,
    expected_hmac: [u8; HMAC_LEN],
}

/// Reader that computes a SHA256 HMAC of the yielded bytes.
type HmacSha256Reader<R> = MacReader<R, Hmac<Sha256>>;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ValidationError {
    /// io error {0}
    Io(#[from] futures::io::Error),
    /// not enough bytes for an HMAC
    TooShort,
    /// HMAC doesn't match: {0}
    InvalidHmac(#[from] HmacMismatchError),
}

#[derive(Copy, Clone, Debug, thiserror::Error)]
#[cfg_attr(test, derive(PartialEq))]
pub struct HmacMismatchError {
    expected: [u8; HMAC_LEN],
    found: [u8; HMAC_LEN],
}

/// Reader that doesn't check the HMAC of the yielded contents.
///
/// Implements [`VerifyHmac`] by always returning success from `verify_hmac`.
pub struct UnvalidatedHmacReader<R>(R);

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum VerifyHmacError {
    /// io error {0}
    Io(#[from] futures::io::Error),
    /// HMAC doesn't match
    HmacMismatch(#[from] HmacMismatchError),
}

#[async_trait(?Send)]
pub trait VerifyHmac: Sized {
    /// Checks that the input that was received has a valid HMAC.
    async fn verify_hmac(self) -> Result<(), VerifyHmacError>;
}

impl<R: AsyncRead + AsyncSkip + Unpin> FramesReader<R> {
    pub async fn new(
        key: &MessageBackupKey,
        mut reader_factory: impl ReaderFactory<Reader = R>,
    ) -> Result<FramesReader<R>, ValidationError> {
        let content_len;
        let expected_hmac;
        {
            let mut reader = reader_factory.make_reader()?;
            content_len = reader
                .stream_len()
                .await?
                .checked_sub(HMAC_LEN as u64)
                .ok_or(ValidationError::TooShort)?;
            log::debug!("found {content_len} bytes with a {HMAC_LEN}-byte HMAC");

            let truncated_reader = reader.borrow_mut().take(content_len);
            let actual_hmac = hmac_sha256(&key.hmac_key, truncated_reader).await?;
            expected_hmac = {
                let mut buf = [0; HMAC_LEN];
                reader.read_exact(&mut buf).await?;
                buf
            };
            if expected_hmac.ct_ne(&actual_hmac).into() {
                let err = HmacMismatchError {
                    expected: expected_hmac,
                    found: actual_hmac,
                };
                log::debug!("invalid HMAC: {err}");
                return Err(err.into());
            }
        };

        let mut content = MacReader::new_sha256(
            reader_factory.make_reader()?.take(content_len),
            &key.hmac_key,
        );

        let mut iv = [0; AES_IV_SIZE];
        content.read_exact(&mut iv).await?;

        let decrypted = Aes256CbcReader::new(&key.aes_key, &iv, content);
        let decompressed = GzipDecoder::new(BufReader::new(decrypted));

        Ok(Self {
            reader: decompressed,
            expected_hmac,
        })
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for FramesReader<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<futures::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl<R> MacReader<R, Hmac<Sha256>> {
    pub fn new_sha256(reader: R, hmac_key: &[u8]) -> Self {
        Self::new(
            reader,
            Hmac::<Sha256>::new_from_slice(hmac_key)
                .expect("HMAC-SHA256 should accept any size key"),
        )
    }
}

impl<R> UnvalidatedHmacReader<R> {
    pub(crate) fn new(reader: R) -> Self {
        Self(reader)
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for UnvalidatedHmacReader<R> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

#[async_trait(?Send)]
impl<R> VerifyHmac for UnvalidatedHmacReader<R> {
    async fn verify_hmac(self) -> Result<(), VerifyHmacError> {
        Ok(())
    }
}

impl std::fmt::Display for HmacMismatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut expected = [0; HMAC_LEN * 2];
        hex::encode_to_slice(self.expected, &mut expected).expect("correct length");
        let expected = std::str::from_utf8(&expected).expect("hex is UTF-8");

        let mut found = [0; HMAC_LEN * 2];
        hex::encode_to_slice(self.found, &mut found).expect("correct length");
        let found = std::str::from_utf8(&found).expect("hex is UTF-8");

        write!(f, "expected {}, found {}", expected, found)
    }
}

#[async_trait(?Send)]
impl<R: AsyncRead + Unpin> VerifyHmac for FramesReader<R> {
    async fn verify_hmac(self) -> Result<(), VerifyHmacError> {
        let Self {
            expected_hmac: expected,
            reader,
        } = self;
        // It's possible that the outer reader didn't read all the way to the
        // end. This can happen when the GZIPped data has trailing padding after
        // the compressed contents. Make sure all the bytes from the inner
        // stream get read through the MacReader input bytes before doing the
        // comparison.
        let mut reader: MacReader<_, _> = reader.into_inner().into_inner().into_inner();
        futures::io::copy(&mut reader, &mut futures::io::sink()).await?;

        let found: [u8; HMAC_LEN] = reader.finalize().into();
        if expected.ct_eq(&found).into() {
            Ok(())
        } else {
            Err(HmacMismatchError { expected, found }.into())
        }
    }
}

async fn hmac_sha256(
    hmac_key: &[u8],
    reader: impl AsyncRead + Unpin,
) -> Result<[u8; HMAC_LEN], futures::io::Error> {
    let mut reader = MacReader::new_sha256(reader, hmac_key);
    let mut writer = futures::io::sink();
    futures::io::copy(&mut reader, &mut writer).await?;
    Ok(reader.finalize().into())
}

#[cfg(test)]
mod test {
    use aes::cipher::crypto_common::rand_core::{OsRng, RngCore as _};
    use array_concat::concat_arrays;
    use assert_matches::assert_matches;
    use async_compression::futures::write::GzipEncoder;
    use futures::executor::block_on;
    use futures::io::{Cursor, ErrorKind};
    use futures::AsyncWriteExt;
    use hex_literal::hex;
    use test_case::test_case;

    use super::*;
    use crate::key::test::FAKE_MESSAGE_BACKUP_KEY;

    #[test]
    fn frame_from_raw_too_short() {
        assert_matches!(
            block_on(FramesReader::new(
                &FAKE_MESSAGE_BACKUP_KEY,
                CursorFactory::new(&[])
            )),
            Err(ValidationError::TooShort)
        );
    }

    #[test]
    fn frame_from_raw_invalid_hmac() {
        const BYTES: [u8; 16] = *b"abcdefghijklmnop";
        const HMAC: [u8; HMAC_LEN] = [0; HMAC_LEN];

        let frame_bytes: [u8; 48] = concat_arrays!(BYTES, HMAC);

        assert_matches!(
            block_on(FramesReader::new(
                &FAKE_MESSAGE_BACKUP_KEY,
                CursorFactory::new(&frame_bytes)
            )),
            Err(ValidationError::InvalidHmac(_))
        );
    }

    #[test_log::test]
    fn frame_failed_decrypt() {
        const BYTES: [u8; 26] = *b"abcdefghijklmnopqrstuvwxyz";
        const VALID_HMAC: [u8; HMAC_LEN] =
            hex!("80f52dcaf00614eb27d19b6a71d3596754b176da14cbe2e9e12f75ad5dc39fc1");
        // Garbage, but with a valid HMAC appended.
        let frame_bytes: [u8; 58] = concat_arrays!(BYTES, VALID_HMAC);

        let mut reader = block_on(FramesReader::new(
            &FAKE_MESSAGE_BACKUP_KEY,
            CursorFactory::new(&frame_bytes),
        ))
        .unwrap_or_else(|e| panic!("expected valid HMAC, got {e}"));

        let mut buf = Vec::new();
        assert_matches!(
            block_on(reader.read_to_end(&mut buf)),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof);
    }

    #[derive(Copy, Clone)]
    enum PadCompressed {
        Pad,
        NoPad,
    }
    use PadCompressed::*;

    async fn make_encrypted(
        key: &MessageBackupKey,
        plaintext: &[u8],
        pad: PadCompressed,
    ) -> Box<[u8]> {
        const PAD_BYTES: [u8; 55] = [0; 55];

        let mut compressed = {
            let mut gz_writer = GzipEncoder::new(Cursor::new(Vec::new()));
            gz_writer
                .write_all(plaintext)
                .await
                .expect("writing to in-memory cursor can't fail");
            gz_writer.close().await.expect("close can't fail");
            gz_writer.into_inner().into_inner()
        };

        match pad {
            NoPad => (),
            Pad => compressed.extend_from_slice(&PAD_BYTES),
        }

        let mut iv = [0; AES_IV_SIZE];
        OsRng.fill_bytes(&mut iv);
        let mut ctext = signal_crypto::aes_256_cbc_encrypt(&compressed, &key.aes_key, &iv)
            .expect("can encrypt");
        drop(compressed);

        // Prepend the IV bytes to the encrypted contents.
        ctext = iv.into_iter().chain(ctext).collect();

        // Append the hmac
        let hmac = hmac_sha256(&key.hmac_key, Cursor::new(&ctext))
            .await
            .expect("can hash");
        ctext.extend_from_slice(&hmac);

        ctext.into_boxed_slice()
    }

    #[test_case(Pad)]
    #[test_case(NoPad)]
    fn frame_round_trip(pad: PadCompressed) {
        const FRAME_DATA: &[u8] = b"this was a triumph";

        let encoded_frame = block_on(make_encrypted(&FAKE_MESSAGE_BACKUP_KEY, FRAME_DATA, pad));

        let mut reader = block_on(FramesReader::new(
            &FAKE_MESSAGE_BACKUP_KEY,
            CursorFactory::new(&encoded_frame),
        ))
        .expect("valid HMAC");
        let mut buf = Vec::new();
        block_on(AsyncReadExt::read_to_end(&mut reader, &mut buf)).expect("can read");

        assert_eq!(buf, FRAME_DATA,);
    }

    #[test_case(Pad)]
    #[test_case(NoPad)]
    fn mismatched_hmac(pad: PadCompressed) {
        // Create two different contents. The first will be read during HMAC
        // verification by FramesReader::new, while the second will actually
        // produce the contents for the reader. Since the contents are
        // different, the HMACs don't match.
        let first_contents = block_on(make_encrypted(
            &FAKE_MESSAGE_BACKUP_KEY,
            b"this was a triumph",
            pad,
        ));
        let second_contents = block_on(make_encrypted(
            &FAKE_MESSAGE_BACKUP_KEY,
            b"THIS WAS A TRIUMPH",
            pad,
        ));

        let reader_factory = LimitedReaderFactory::new([
            Cursor::new(&first_contents),
            Cursor::new(&second_contents),
        ]);

        let mut reader = block_on(FramesReader::new(&FAKE_MESSAGE_BACKUP_KEY, reader_factory))
            .expect("encoded HMAC is valid");
        block_on(futures::io::copy(&mut reader, &mut futures::io::sink())).expect("can read");

        let hmac_tail = |bytes: &[u8]| bytes[bytes.len() - HMAC_LEN..].try_into().unwrap();
        let hmac_err = block_on(reader.verify_hmac());
        let err = assert_matches!( hmac_err, Err(VerifyHmacError::HmacMismatch(e)) => e);
        assert_eq!(
            err,
            HmacMismatchError {
                expected: hmac_tail(&first_contents),
                found: hmac_tail(&second_contents)
            }
        );
    }
}
