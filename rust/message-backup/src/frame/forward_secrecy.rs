//
// Copyright (C) 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::io;

use futures::AsyncRead;
use libsignal_account_keys::BACKUP_FORWARD_SECRECY_TOKEN_LEN;
use libsignal_svrb::proto::backup_metadata::MetadataPb;
use libsignal_svrb::proto::backup_metadata::metadata_pb::Pair as ForwardSecrecyPair;
use protobuf::Message;
use sha2::Digest;

use crate::frame::{FramesReader, ValidationError};
use crate::log_unknown_fields;
use crate::parse::VarintDelimitedReader;

pub const MAGIC_NUMBER: &[u8] = b"SBACKUP\x01";
// From HMAC_SHA256_TRUNCATED_BYTES in net's svrb.rs.
const CT_MAC_LEN: usize = 16;
const BACKUP_METADATA_IV_LEN: usize = 12;

impl<R: AsyncRead + Unpin> FramesReader<R> {
    pub async fn verify_metadata(reader: &mut R) -> Result<(), ValidationError> {
        let mut metadata_frame_reader = VarintDelimitedReader::new(reader);
        let metadata = metadata_frame_reader
            .read_next()
            .await?
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;

        let MetadataPb {
            iv,
            pair: forward_secrecy_pairs,
            special_fields,
        } = MetadataPb::parse_from_bytes(&metadata)
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
            more => return Err(ValidationError::TooManyForwardSecrecyPairs(more)),
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
            if ct.len() != BACKUP_FORWARD_SECRECY_TOKEN_LEN + CT_MAC_LEN {
                return Err(ValidationError::InvalidLength {
                    field: "pair.ct",
                    expected: BACKUP_FORWARD_SECRECY_TOKEN_LEN + CT_MAC_LEN,
                    actual: ct.len(),
                });
            }
            if pw_salt.is_empty() {
                return Err(ValidationError::MissingMetadataField("pair.pw_salt"));
            }
            // Strictly, the salt for an HKDF operation doesn't have any fixed size; however, salts
            // longer than the hash output size are hashed down ahead of time, so the effective
            // maximum size for a salt is the hash output size.
            if pw_salt.len() != sha2::Sha256::output_size() {
                return Err(ValidationError::InvalidLength {
                    field: "pair.pw_salt",
                    expected: sha2::Sha256::output_size(),
                    actual: pw_salt.len(),
                });
            }

            // We don't actually validate the salts and ciphertexts; we don't have the keys to do so. We
            // could make them accessible, but that would complicate all the APIs around backup
            // generation as well, having to expose the details of blobs that would otherwise be opaque
            // at higher levels.
        }

        if iv.len() != BACKUP_METADATA_IV_LEN {
            return Err(ValidationError::InvalidLength {
                field: "iv",
                expected: BACKUP_METADATA_IV_LEN,
                actual: iv.len(),
            });
        }

        // Verify that no bytes are left in the VarintDelimitedReader's buffer.
        _ = metadata_frame_reader.into_inner();
        Ok(())
    }
}

/// Logs if an observed magic number is "SBACKUPx", where 'x' is something other than the '1' from
/// `MAGIC_NUMBER` that doubles as a structural version.
pub(super) fn warn_if_close_to_magic_number(number: [u8; MAGIC_NUMBER.len()]) {
    let prefix = &MAGIC_NUMBER[..MAGIC_NUMBER.len() - 1];
    if number.starts_with(prefix) {
        log::warn!(
            "backup starts with '{}' but the final byte is {:x}; treating as ciphertext-only",
            std::str::from_utf8(prefix).expect("valid ASCII"),
            number.last().expect("more than 0 bytes"),
        )
    }
}

#[cfg(test)]
pub(crate) mod test {
    use futures::FutureExt;
    use test_case::test_case;

    use super::*;

    pub(crate) fn test_metadata() -> MetadataPb {
        MetadataPb {
            iv: vec![0u8; 12],
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

    fn process(input: &[u8]) -> Result<(), ValidationError> {
        FramesReader::verify_metadata(&mut futures::io::Cursor::new(input))
            .now_or_never()
            .expect("sync")
    }

    #[test]
    fn valid() {
        process(
            &test_metadata()
                .write_length_delimited_to_bytes()
                .expect("can serialize"),
        )
        .expect("valid")
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
    #[test_case(MetadataPb {
        pair: vec![Default::default(), Default::default(), Default::default()],
        ..Default::default()
    } => matches ValidationError::TooManyForwardSecrecyPairs(3))]
    fn invalid(metadata: MetadataPb) -> ValidationError {
        process(
            &metadata
                .write_length_delimited_to_bytes()
                .expect("can serialize"),
        )
        .expect_err("should fail")
    }
}
