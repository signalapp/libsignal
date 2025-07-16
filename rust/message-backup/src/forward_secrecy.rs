//
// Copyright (C) 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io;

use futures::{AsyncRead, AsyncReadExt as _};
use libsignal_account_keys::proto::backup_metadata::metadata_pb::Pair as ForwardSecrecyPair;
use libsignal_account_keys::proto::backup_metadata::MetadataPb;
use mediasan_common::{AsyncSkip, AsyncSkipExt as _};
use protobuf::Message;

use crate::frame::{FramesReader, ReaderFactory, ValidationError};
use crate::key::MessageBackupKey;
use crate::log_unknown_fields;
use crate::parse::VarintDelimitedReader;

pub const MAGIC_NUMBER: &[u8] = b"SBACKUP\x01";

impl<R: AsyncRead + AsyncSkip + Unpin> FramesReader<R> {
    pub async fn for_forward_secrecy_format(
        key: &MessageBackupKey,
        mut reader_factory: impl ReaderFactory<Reader = R>,
    ) -> Result<Self, ValidationError> {
        let mut reader = reader_factory.make_reader()?;

        let mut magic_number = [0; 8];
        reader.read_exact(&mut magic_number).await?;
        if magic_number != MAGIC_NUMBER {
            return Err(ValidationError::UnrecognizedMagicNumber(
                u64::from_be_bytes(magic_number),
            ));
        }

        let mut metadata_frame_reader = VarintDelimitedReader::new(reader);
        let metadata = metadata_frame_reader
            .read_next()
            .await?
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        validate_metadata(&metadata)?;

        let mut reader = metadata_frame_reader.into_inner();
        let start_of_encrypted_data = reader.stream_position().await?;
        let (content_len, hmac) = FramesReader::check_hmac(key, reader).await?;

        let mut new_reader = reader_factory.make_reader()?;
        new_reader.skip(start_of_encrypted_data).await?;
        Self::with_separate_hmac(key, new_reader.take(content_len), hmac).await
    }
}

fn validate_metadata(metadata: &[u8]) -> Result<(), ValidationError> {
    let MetadataPb {
        pair: forward_secrecy_pairs,
        special_fields,
    } = MetadataPb::parse_from_bytes(metadata)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

    // Since MetadataPb is from outside this crate, we can't derive VisitUnknownFields for it.
    // We could implement it manually, but in practice it's close enough to approximate it here.
    // If we end up with a more deeply nested structure in the future we can revisit.
    log_unknown_fields(&special_fields, "unencrypted metadata");

    match forward_secrecy_pairs.len() {
        0 => return Err(ValidationError::MissingMetadataField("pair")),
        1..=2 => {
            // 2 is the common case: one key currently on the service, one key to replace it.
            // 1 happens when there's no key currently on the service (e.g. the first backup).
        }
        more => {
            // Nothing breaks if we have more pairs, but we shouldn't need it either.
            log::warn!("found {more} forward secrecy pairs in unencrypted metadata");
        }
    }

    for pair_pb in forward_secrecy_pairs {
        let ForwardSecrecyPair {
            ct,
            pw_salt,
            special_fields,
        } = pair_pb;
        log_unknown_fields(&special_fields, "unencrypted metadata 'pair'");
        if ct.is_empty() {
            return Err(ValidationError::MissingMetadataField("pair.ct"));
        }
        if pw_salt.is_empty() {
            return Err(ValidationError::MissingMetadataField("pair.pw_salt"));
        }

        // We don't actually validate the salts and ciphertexts; we don't have the keys to do so. We
        // could make them accessible, but that would complicate all the APIs around backup
        // generation as well, having to expose the details of blobs that would otherwise be opaque
        // at higher levels.
    }

    Ok(())
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    // Avoid colliding with std::concat_bytes.
    use const_str::concat_bytes as concat_b;
    use futures::FutureExt;
    use hmac::digest::FixedOutput;
    use hmac::Mac;
    use test_case::test_case;

    use super::*;
    use crate::frame::{CursorFactory, AES_IV_SIZE};
    use crate::key::test::FAKE_MESSAGE_BACKUP_KEY;

    fn process(input: &[u8]) -> Result<(), ValidationError> {
        let factory = CursorFactory::new(input);
        _ = FramesReader::for_forward_secrecy_format(&FAKE_MESSAGE_BACKUP_KEY, factory)
            .now_or_never()
            .expect("sync")?;
        Ok(())
    }

    fn assert_io_error(kind: io::ErrorKind) -> impl Fn(ValidationError) {
        move |e| assert_matches!(e, ValidationError::Io(e) if e.kind() == kind)
    }

    #[test_case(b"" => using assert_io_error(io::ErrorKind::UnexpectedEof))]
    #[test_case(b"1234" => using assert_io_error(io::ErrorKind::UnexpectedEof))]
    #[test_case(b"12345678" => matches ValidationError::UnrecognizedMagicNumber(0x3132333435363738))]
    #[test_case(MAGIC_NUMBER => using assert_io_error(io::ErrorKind::UnexpectedEof))]
    #[test_case(concat_b!(MAGIC_NUMBER, 1) => using assert_io_error(io::ErrorKind::UnexpectedEof))]
    #[test_case(concat_b!(MAGIC_NUMBER, [1, 0]) => using assert_io_error(io::ErrorKind::InvalidData))]
    #[test_case(concat_b!(MAGIC_NUMBER, [0x80, 0x80, 0x80, 0x80, 0x80, 0x01]) => using assert_io_error(io::ErrorKind::InvalidData))]
    fn invalid_start_of_file(input: &[u8]) -> ValidationError {
        process(input).expect_err("should fail")
    }

    fn test_metadata() -> MetadataPb {
        MetadataPb {
            pair: vec![
                ForwardSecrecyPair {
                    ct: vec![1; 48],
                    pw_salt: vec![2; 32],
                    ..Default::default()
                },
                ForwardSecrecyPair {
                    ct: vec![3; 48],
                    pw_salt: vec![4; 32],
                    ..Default::default()
                },
            ],
            ..Default::default()
        }
    }

    #[test_case(MetadataPb::new() => matches ValidationError::MissingMetadataField("pair"))]
    #[test_case(MetadataPb {
        pair: vec![ForwardSecrecyPair { ct: vec![1; 48], ..Default::default() }],
        ..Default::default()
    } => matches ValidationError::MissingMetadataField("pair.pw_salt"))]
    #[test_case(MetadataPb {
        pair: vec![ForwardSecrecyPair { pw_salt: vec![1; 32], ..Default::default() }],
        ..Default::default()
    } => matches ValidationError::MissingMetadataField("pair.ct"))]
    #[test_case(test_metadata() => using assert_io_error(io::ErrorKind::UnexpectedEof))]
    fn invalid_with_metadata(metadata: MetadataPb) -> ValidationError {
        let mut input = vec![];
        input.extend_from_slice(MAGIC_NUMBER);
        metadata
            .write_length_delimited_to_vec(&mut input)
            .expect("will not run out of memory");
        process(&input).expect_err("should fail")
    }

    #[test]
    fn structurally_valid_empty_backup() {
        let iv = [4; AES_IV_SIZE];
        let mut hmac =
            hmac::Hmac::<sha2::Sha256>::new_from_slice(&FAKE_MESSAGE_BACKUP_KEY.hmac_key)
                .expect("HMAC accepts any key length");
        hmac.update(&iv);
        let full_file = [
            MAGIC_NUMBER,
            &test_metadata()
                .write_length_delimited_to_bytes()
                .expect("will not run out of memory"),
            &iv,
            &hmac.finalize_fixed(),
        ]
        .concat();
        process(&full_file).expect("should succeed")
    }
}
