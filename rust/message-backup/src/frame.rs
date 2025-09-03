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
pub mod forward_secrecy;
mod mac_read;
mod reader_factory;
mod unpad;

#[cfg(feature = "test-util")]
pub use aes_read::AES_KEY_SIZE;
#[cfg_attr(feature = "test-util", visibility::make(pub))]
use aes_read::{AES_IV_SIZE, Aes256CbcReader};
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
    /// {0}
    Io(#[from] futures::io::Error),
    /// missing field '{0}' in unencrypted metadata
    MissingMetadataField(&'static str),
    /// unencrypted metadata field '{field}' was {actual} bytes long (expected {expected})
    InvalidLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    /// unencrypted metadata contains {0} forward secrecy pairs
    TooManyForwardSecrecyPairs(usize),
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
    ) -> Result<Self, ValidationError> {
        let mut reader = reader_factory.make_reader()?;

        let mut maybe_magic_number = [0; forward_secrecy::MAGIC_NUMBER.len()];
        reader.read_exact(&mut maybe_magic_number).await?;
        let (start_of_encrypted_data, extra_bytes_to_hmac) =
            if maybe_magic_number == forward_secrecy::MAGIC_NUMBER {
                Self::verify_metadata(&mut reader).await?;
                let start_of_encrypted_data = reader.stream_position().await?;
                (start_of_encrypted_data, &[][..])
            } else {
                // Legacy format, with no magic number or unencrypted metadata blob.
                forward_secrecy::warn_if_close_to_magic_number(maybe_magic_number);
                (0, &maybe_magic_number[..])
            };

        let (content_len, hmac) = Self::check_hmac(key, extra_bytes_to_hmac, reader).await?;

        let mut new_reader = reader_factory.make_reader()?;
        new_reader.skip(start_of_encrypted_data).await?;
        Self::with_separate_hmac(key, new_reader.take(content_len), hmac).await
    }

    /// Checks the contents of `reader` against the HMAC key in `key`.
    ///
    /// Assumes the last chunk of bytes will be the HMAC. Returns the covered content length (the
    /// total length minus the length of the HMAC) along with the HMAC in question (so it can be
    /// checked again, post-read).
    ///
    /// `extra_bytes_to_hmac` can be used to include bytes that have already been read from
    /// `reader`; they will be inserted at the front of the stream for the MAC calculation and
    /// included in the returned content length.
    async fn check_hmac(
        key: &MessageBackupKey,
        extra_bytes_to_hmac: &[u8],
        mut reader: R,
    ) -> Result<(u64, [u8; HMAC_LEN]), ValidationError> {
        let position = reader.stream_position().await?;
        let content_len = reader
            .stream_len()
            .await?
            .checked_sub(position + HMAC_LEN as u64)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        log::debug!("found {content_len} bytes with a {HMAC_LEN}-byte HMAC");

        let truncated_reader = reader.borrow_mut().take(content_len);
        let actual_hmac = hmac_sha256(&key.hmac_key, extra_bytes_to_hmac, truncated_reader).await?;
        let expected_hmac = {
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
        Ok((
            content_len + extra_bytes_to_hmac.len() as u64,
            expected_hmac,
        ))
    }

    /// Creates a `FramesReader` with the specified `key` and `expected_hmac`.
    ///
    /// `reader` should already be truncated to only the bytes covered by the HMAC, hence the type.
    async fn with_separate_hmac(
        key: &MessageBackupKey,
        reader: futures::io::Take<R>,
        expected_hmac: [u8; HMAC_LEN],
    ) -> Result<Self, ValidationError> {
        let mut content = MacReader::new_sha256(reader, &key.hmac_key);

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

        write!(f, "expected {expected}, found {found}")
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

/// Convenience wrapper around HMAC-ing the whole contents of an [`AsyncRead`].
///
/// `extra_bytes_to_hmac` can be used to include bytes that have already been read from `reader`;
/// they will be inserted at the front of the stream for the MAC calculation.
async fn hmac_sha256(
    hmac_key: &[u8],
    extra_bytes_to_hmac: &[u8],
    reader: impl AsyncRead + Unpin,
) -> Result<[u8; HMAC_LEN], futures::io::Error> {
    let mut reader = MacReader::new_sha256(
        futures::io::Cursor::new(extra_bytes_to_hmac).chain(reader),
        hmac_key,
    );
    let mut writer = futures::io::sink();
    futures::io::copy(&mut reader, &mut writer).await?;
    Ok(reader.finalize().into())
}

#[cfg(test)]
mod test {
    use aes::cipher::crypto_common::rand_core::{OsRng, RngCore as _};
    use assert_matches::assert_matches;
    use async_compression::futures::write::GzipEncoder;
    use const_str::{concat_bytes, hex};
    use futures::AsyncWriteExt;
    use futures::executor::block_on;
    use futures::io::{Cursor, ErrorKind};
    use protobuf::Message as _;
    use test_case::{test_case, test_matrix};

    use super::*;
    use crate::frame::forward_secrecy::MAGIC_NUMBER;
    use crate::key::test::FAKE_MESSAGE_BACKUP_KEY;

    #[test]
    fn frame_from_raw_too_short() {
        assert_matches!(
            block_on(FramesReader::new(
                &FAKE_MESSAGE_BACKUP_KEY,
                CursorFactory::new(&[])
            )),
            Err(ValidationError::Io(e)) if e.kind() == ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn frame_from_raw_invalid_hmac() {
        const BYTES: [u8; 16] = *b"abcdefghijklmnop";
        const HMAC: [u8; HMAC_LEN] = [0; HMAC_LEN];

        let frame_bytes: [u8; 48] = *concat_bytes!(BYTES, HMAC);

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
            hex!("9cc04bb3286dfb4f3f2ba292c9ef192bbec3d8b244aa65e69341a935f61f4fda");
        // Garbage, but with a valid HMAC appended.
        let frame_bytes: [u8; 58] = *concat_bytes!(BYTES, VALID_HMAC);

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
        let hmac = hmac_sha256(&key.hmac_key, &[], Cursor::new(&ctext))
            .await
            .expect("can hash");
        ctext.extend_from_slice(&hmac);

        ctext.into_boxed_slice()
    }

    #[derive(Clone, Copy)]
    enum Format {
        Legacy,
        Modern,
    }

    #[test_matrix([Pad, NoPad], [Format::Legacy, Format::Modern])]
    fn frame_round_trip(pad: PadCompressed, format: Format) {
        const FRAME_DATA: &[u8] = b"this was a triumph";

        let encoded_frame = block_on(make_encrypted(&FAKE_MESSAGE_BACKUP_KEY, FRAME_DATA, pad));

        let full_file = match format {
            Format::Legacy => encoded_frame.into_vec(),
            Format::Modern => [
                MAGIC_NUMBER,
                &forward_secrecy::test::test_metadata()
                    .write_length_delimited_to_bytes()
                    .expect("will not run out of memory"),
                &encoded_frame,
            ]
            .concat(),
        };

        let mut reader = block_on(FramesReader::new(
            &FAKE_MESSAGE_BACKUP_KEY,
            CursorFactory::new(&full_file),
        ))
        .expect("valid HMAC");
        let mut buf = Vec::new();
        block_on(AsyncReadExt::read_to_end(&mut reader, &mut buf)).expect("can read");

        assert_eq!(buf, FRAME_DATA);
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

    fn assert_io_error(kind: ErrorKind) -> impl Fn(ValidationError) {
        move |e| assert_matches!(e, ValidationError::Io(e) if e.kind() == kind)
    }

    #[test_case(b"" => using assert_io_error(ErrorKind::UnexpectedEof))]
    #[test_case(b"1234" => using assert_io_error(ErrorKind::UnexpectedEof))]
    #[test_case(b"12345678" => using assert_io_error(ErrorKind::UnexpectedEof))]
    #[test_case(MAGIC_NUMBER => using assert_io_error(ErrorKind::UnexpectedEof))]
    #[test_case(const_str::concat_bytes!(MAGIC_NUMBER, 1) => using assert_io_error(ErrorKind::UnexpectedEof))]
    #[test_case(const_str::concat_bytes!(MAGIC_NUMBER, [1, 0]) => using assert_io_error(ErrorKind::InvalidData))]
    #[test_case(const_str::concat_bytes!(MAGIC_NUMBER, [0x80, 0x80, 0x80, 0x80, 0x80, 0x01]) => using assert_io_error(ErrorKind::InvalidData))]
    fn invalid_start_of_file(input: &[u8]) -> ValidationError {
        block_on(FramesReader::new(
            &FAKE_MESSAGE_BACKUP_KEY,
            CursorFactory::new(&input),
        ))
        .expect_err("should fail")
    }
}
