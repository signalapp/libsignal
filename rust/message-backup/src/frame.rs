//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::BorrowMut;

use aes::cipher::Unsigned;
use async_compression::futures::bufread::GzipDecoder;
use futures::io::{BufReader, Take};
use futures::{AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt as _};
use hmac::digest::OutputSizeUser;
use hmac::{Hmac, Mac as _};
use sha2::Sha256;
use subtle::ConstantTimeEq as _;

use crate::frame::aes_read::Aes256CbcReader;
use crate::key::MessageBackupKey;

mod aes_read;
mod block_stream;
mod cbc;
mod unpad;

const HMAC_LEN: usize = <<Hmac<Sha256> as OutputSizeUser>::OutputSize as Unsigned>::USIZE;

#[derive(Debug)]
pub struct FramesReader<R: AsyncRead + Unpin> {
    reader: GzipDecoder<BufReader<Aes256CbcReader<Take<R>>>>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ValidationError {
    /// io error {0}
    Io(#[from] futures::io::Error),
    /// not enough bytes for an HMAC
    TooShort,
    /// HMAC doesn't match
    InvalidHmac,
}

impl<R: AsyncRead + AsyncSeek + Unpin> FramesReader<R> {
    #[allow(unused)]
    pub(crate) async fn new(
        key: &MessageBackupKey,
        mut reader: R,
    ) -> Result<FramesReader<R>, ValidationError> {
        let total_len = reader.seek(futures::io::SeekFrom::End(0)).await?;
        let content_len = total_len
            .checked_sub(HMAC_LEN as u64)
            .ok_or(ValidationError::TooShort)?;

        reader.seek(futures::io::SeekFrom::Start(0)).await?;
        log::debug!("found {content_len} bytes with a {HMAC_LEN}-byte HMAC");

        let truncated_reader = reader.borrow_mut().take(content_len);
        let actual_hmac = hmac_sha256(&key.hmac_key, truncated_reader).await?;

        let expected_hmac = {
            let mut buf = [0; HMAC_LEN];
            reader.read_exact(&mut buf).await?;
            buf
        };

        if expected_hmac.ct_ne(&actual_hmac).into() {
            log::debug!("expected {expected_hmac:02x?}, got {actual_hmac:02x?}");
            return Err(ValidationError::InvalidHmac);
        }

        reader.seek(futures::io::SeekFrom::Start(0)).await?;
        let content = reader.take(content_len);
        let decrypted = Aes256CbcReader::new(&key.aes_key, &key.iv, content);
        let decompressed = GzipDecoder::new(BufReader::new(decrypted));

        Ok(Self {
            reader: decompressed,
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

async fn hmac_sha256(
    hmac_key: &[u8],
    reader: impl AsyncRead,
) -> Result<[u8; HMAC_LEN], futures::io::Error> {
    let mut hmac =
        Hmac::<Sha256>::new_from_slice(hmac_key).expect("HMAC-SHA256 should accept any size key");
    let mut writer = futures::io::AllowStdIo::new(&mut hmac);
    futures::io::copy(reader, &mut writer).await?;

    Ok(hmac.finalize().into_bytes().into())
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
                Cursor::new(&[])
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
                Cursor::new(frame_bytes)
            )),
            Err(ValidationError::InvalidHmac)
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
            Cursor::new(frame_bytes),
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
            Cursor::new(encoded_frame),
        ))
        .expect("valid HMAC");
        let mut buf = Vec::new();
        block_on(AsyncReadExt::read_to_end(&mut reader, &mut buf)).expect("can read");

        assert_eq!(buf, FRAME_DATA,);
    }
}
