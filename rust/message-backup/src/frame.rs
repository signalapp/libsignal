//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::BorrowMut;

use aes::cipher::Unsigned;
use async_compression::futures::bufread::GzipDecoder;
use futures::io::{BufReader, Take};
use futures::{AsyncRead, AsyncReadExt};
use hmac::digest::OutputSizeUser;
use hmac::{Hmac, Mac as _};
use mediasan_common::{AsyncSkip, AsyncSkipExt as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

use crate::frame::aes_read::Aes256CbcReader;
use crate::frame::mac_read::MacReader;
use crate::key::MessageBackupKey;

mod aes_read;
mod block_stream;
mod cbc;
mod mac_read;
mod reader_factory;
mod unpad;

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
    /// HMAC doesn't match
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

pub trait VerifyHmac: Sized {
    /// Checks that the input that was received has a valid HMAC.
    fn verify_hmac(self) -> Result<(), HmacMismatchError>;
}

impl<R: AsyncRead + AsyncSkip + Unpin> FramesReader<R> {
    pub(crate) async fn new(
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

        let content = MacReader::new_sha256(
            reader_factory.make_reader()?.take(content_len),
            &key.hmac_key,
        );
        let decrypted = Aes256CbcReader::new(&key.aes_key, &key.iv, content);
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
    fn new_sha256(reader: R, hmac_key: &[u8]) -> Self {
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

impl<R> VerifyHmac for UnvalidatedHmacReader<R> {
    fn verify_hmac(self) -> Result<(), HmacMismatchError> {
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

impl<R: AsyncRead + Unpin> VerifyHmac for FramesReader<R> {
    fn verify_hmac(self) -> Result<(), HmacMismatchError> {
        let Self {
            expected_hmac: expected,
            reader,
        } = self;
        let reader = reader.into_inner().into_inner().into_inner();
        let found: [u8; HMAC_LEN] = reader.finalize().into();
        if expected.ct_eq(&found).into() {
            Ok(())
        } else {
            Err(HmacMismatchError { expected, found })
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
    use futures::io::ErrorKind;

    use array_concat::concat_arrays;
    use assert_matches::assert_matches;
    use async_compression::futures::write::GzipEncoder;
    use futures::executor::block_on;
    use futures::io::Cursor;
    use futures::AsyncWriteExt;
    use hex_literal::hex;

    use crate::key::test::FAKE_MESSAGE_BACKUP_KEY;

    use super::*;

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
        const BYTES: [u8; 10] = *b"abcdefghij";
        const VALID_HMAC: [u8; HMAC_LEN] =
            hex!("2e4a0e7bc18de0ca7f40ab3537f0f97a06e56c3a5e4a3526c95780f21c3f549e");
        // Garbage, but with a valid HMAC appended.
        let frame_bytes: [u8; 42] = concat_arrays!(BYTES, VALID_HMAC);

        let mut reader = block_on(FramesReader::new(
            &FAKE_MESSAGE_BACKUP_KEY,
            CursorFactory::new(&frame_bytes),
        ))
        .expect("valid HMAC");

        let mut buf = Vec::new();
        assert_matches!(
            block_on(reader.read_to_end(&mut buf)),
            Err(e) if e.kind() == ErrorKind::UnexpectedEof);
    }

    async fn make_encrypted(key: &MessageBackupKey, plaintext: &[u8]) -> Box<[u8]> {
        let compressed = {
            let mut gz_writer = GzipEncoder::new(Cursor::new(Vec::new()));
            gz_writer
                .write_all(plaintext)
                .await
                .expect("writing to in-memory cursor can't fail");
            gz_writer.close().await.expect("close can't fail");
            gz_writer.into_inner().into_inner()
        };

        let mut ctext = signal_crypto::aes_256_cbc_encrypt(&compressed, &key.aes_key, &key.iv)
            .expect("can encrypt");
        drop(compressed);

        // Append the hmac
        let hmac = hmac_sha256(&key.hmac_key, Cursor::new(&ctext))
            .await
            .expect("can hash");
        ctext.extend_from_slice(&hmac);

        ctext.into_boxed_slice()
    }

    #[test]
    fn frame_round_trip() {
        const FRAME_DATA: &[u8] = b"this was a triumph";

        let encoded_frame = block_on(make_encrypted(&FAKE_MESSAGE_BACKUP_KEY, FRAME_DATA));

        let mut reader = block_on(FramesReader::new(
            &FAKE_MESSAGE_BACKUP_KEY,
            CursorFactory::new(&encoded_frame),
        ))
        .expect("valid HMAC");
        let mut buf = Vec::new();
        block_on(AsyncReadExt::read_to_end(&mut reader, &mut buf)).expect("can read");

        assert_eq!(buf, FRAME_DATA,);
    }

    #[test]
    fn mismatched_hmac() {
        // Create two different contents. The first will be read during HMAC
        // verification by FramesReader::new, while the second will actually
        // produce the contents for the reader. Since the contents are
        // different, the HMACs don't match.
        let first_contents = block_on(make_encrypted(
            &FAKE_MESSAGE_BACKUP_KEY,
            b"this was a triumph",
        ));
        let second_contents = block_on(make_encrypted(
            &FAKE_MESSAGE_BACKUP_KEY,
            b"THIS WAS A TRIUMPH",
        ));

        let reader_factory = LimitedReaderFactory::new([
            Cursor::new(&first_contents),
            Cursor::new(&second_contents),
        ]);

        let mut reader = block_on(FramesReader::new(&FAKE_MESSAGE_BACKUP_KEY, reader_factory))
            .expect("encoded HMAC is valid");
        block_on(futures::io::copy(&mut reader, &mut futures::io::sink())).expect("can read");

        let hmac_tail = |bytes: &[u8]| bytes[bytes.len() - HMAC_LEN..].try_into().unwrap();
        assert_eq!(
            reader.verify_hmac(),
            Err(HmacMismatchError {
                expected: hmac_tail(&first_contents),
                found: hmac_tail(&second_contents)
            })
        )
    }
}
