//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Encrypted, caller-owned metadata attached to an account's multi-factor authentication (MFA)
//! keys.
//!
//! The server stores each confirmed MFA key alongside an opaque, fixed-size blob of metadata that
//! only the account's own devices can read. libsignal owns the format entirely. Clients only ever
//! see an [`MfaMetadata`] and the chat layer only ever sees an [`EncryptedMfaMetadata`].
//!
//! The encrypted form is exactly [`MFA_METADATA_CIPHERTEXT_LEN`] bytes:
//!
//! ```text
//! [ 16 bytes random IV | 112 bytes AES-256-CBC ciphertext | 32 bytes HMAC-SHA256(IV | ciphertext) ]
//! ```
//!
//! The plaintext is the protobuf message
//!
//! ```text
//! message MfaKeyMetadataPlaintext {
//!   uint64 creation_epoch_time_seconds = 1;
//!   string key_name = 2;
//! }
//! ```
//!
//! (see `proto/mfa_metadata.proto`) padded to 112 bytes PKCS#7-style (every padding byte is the
//! number of padding bytes), so the ciphertext length does not leak the length of the name.
//!
//! 112 bytes leaves room for the largest encoding of the fields (1 byte of padding, 2 field tags,
//! 1 length prefix, 10 bytes of varint timestamp) plus [`MFA_KEY_NAME_MAX_LEN`] bytes of UTF-8 name.
//!
//! This differs from `signal_crypto`'s `aes_256_cbc_encrypt`, which pads to the next multiple of
//! 16 bytes, while this method pads up to the fixed [`MFA_METADATA_CIPHERTEXT_LEN`] always.
//!
//! The AES and HMAC keys are derived from the account's SVR key; see
//! [`SvrKey::derive_mfa_metadata_keys`].

use std::num::NonZeroU8;

use aes::Aes256;
use aes::cipher::block_padding::NoPadding;
use aes::cipher::{BlockModeDecrypt as _, BlockModeEncrypt as _, KeyIvInit as _};
use hmac::{Hmac, KeyInit as _, Mac as _};
use libsignal_core::LogSafeDisplay;
use libsignal_protocol::Timestamp;
use protobuf::Message as _;
use rand::CryptoRng;
use sha2::Sha256;

use crate::proto::mfa_metadata::MfaKeyMetadataPlaintext;
use crate::{MfaMetadataKeys, SvrKey};

/// The exact length, in bytes, of the encrypted metadata attached to a confirmed MFA key.
///
/// The server rejects metadata ciphertexts of any other length.
pub const MFA_METADATA_CIPHERTEXT_LEN: usize = 160;

/// The maximum length, in UTF-8 bytes, of an MFA key's name.
pub const MFA_KEY_NAME_MAX_LEN: usize = 98;

const IV_LEN: usize = 16;
const PADDED_PLAINTEXT_LEN: usize = 112;

#[derive(Clone, PartialEq, Eq)]
pub struct MfaMetadata {
    name: String,
    created_at: Timestamp,
}

impl MfaMetadata {
    /// Creates metadata for an MFA key.
    ///
    /// Fails if `name` is longer than [`MFA_KEY_NAME_MAX_LEN`] bytes of UTF-8 or contains U+0000.
    ///
    /// `created_at` is stored with one-second granularity, so a value read back from the server
    /// may be truncated relative to the value that was written.
    pub fn new(name: String, created_at: Timestamp) -> Result<Self, InvalidMfaKeyName> {
        if name.contains('\0') {
            return Err(InvalidMfaKeyName::ContainsNull);
        }
        if name.len() > MFA_KEY_NAME_MAX_LEN {
            return Err(InvalidMfaKeyName::TooLong);
        }
        Ok(Self { name, created_at })
    }

    /// A human-readable name for the key, at most [`MFA_KEY_NAME_MAX_LEN`] bytes of UTF-8 and not
    /// containing U+0000.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// When the key was created.
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// Encrypts this metadata for storage on the server, using keys derived from `svr_key`.
    ///
    /// Only the same `svr_key` can decrypt the result; see [`EncryptedMfaMetadata::decrypt`].
    pub fn encrypt(&self, svr_key: &SvrKey, rng: &mut dyn CryptoRng) -> EncryptedMfaMetadata {
        let Self { name, created_at } = self;
        let creation_epoch_time_seconds = created_at.epoch_millis() / 1000;
        let mut plaintext = MfaKeyMetadataPlaintext {
            creation_epoch_time_seconds,
            key_name: name.clone(),
            special_fields: Default::default(),
        }
        .write_to_bytes()
        .expect("can serialize");
        // There is always at least one byte of padding; the length limits guarantee it, and the
        // decoder relies on it to find the padding length in the last byte.
        let padding_len = PADDED_PLAINTEXT_LEN
            .checked_sub(plaintext.len())
            .expect("name length limit keeps the encoding under the padded length");
        let padding_byte = u8::try_from(padding_len).expect("PADDED_PLAINTEXT_LEN fits in a byte");
        let padding_byte = NonZeroU8::new(padding_byte)
            .expect("name length limit leaves at least one byte of padding");
        plaintext.resize(PADDED_PLAINTEXT_LEN, padding_byte.get());

        let keys = svr_key.derive_mfa_metadata_keys();
        let mut result = [0; MFA_METADATA_CIPHERTEXT_LEN];
        let (iv, rest) = result
            .split_first_chunk_mut::<IV_LEN>()
            .expect("buffer is longer than the IV");
        let (ciphertext, mac) = rest.split_at_mut(PADDED_PLAINTEXT_LEN);
        rng.fill_bytes(iv);
        cbc::Encryptor::<Aes256>::new(&keys.cipher_key.into(), (&*iv).into())
            .encrypt_padded_b2b::<NoPadding>(&plaintext, ciphertext)
            .expect("output buffer is exactly the padded plaintext length");
        let mut hmac = mfa_metadata_mac(&keys);
        hmac.update(iv);
        hmac.update(ciphertext);
        mac.copy_from_slice(&hmac.finalize().into_bytes());
        EncryptedMfaMetadata(result)
    }
}

impl std::fmt::Debug for MfaMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { name, created_at } = self;
        f.debug_struct("MfaMetadata")
            .field("name.len", &name.len())
            .field("created_at", created_at)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct EncryptedMfaMetadata([u8; MFA_METADATA_CIPHERTEXT_LEN]);

impl EncryptedMfaMetadata {
    pub fn as_bytes(&self) -> &[u8; MFA_METADATA_CIPHERTEXT_LEN] {
        &self.0
    }

    /// Authenticates and decrypts the metadata using keys derived from `svr_key`.
    ///
    /// This may fail if e.g. the given key does not decrypt the given ciphertext, or
    /// if the ciphertext has been tampered with.
    pub fn decrypt(&self, svr_key: &SvrKey) -> Result<MfaMetadata, InvalidMfaMetadata> {
        let keys = svr_key.derive_mfa_metadata_keys();
        let (iv, rest) = self
            .0
            .split_first_chunk::<IV_LEN>()
            .expect("buffer is longer than the IV");
        let (ciphertext, mac) = rest.split_at(PADDED_PLAINTEXT_LEN);

        let mut hmac = mfa_metadata_mac(&keys);
        hmac.update(iv);
        hmac.update(ciphertext);
        hmac.verify_slice(mac).map_err(|_| InvalidMfaMetadata)?;

        let padded = cbc::Decryptor::<Aes256>::new(&keys.cipher_key.into(), iv.into())
            .decrypt_padded_vec::<NoPadding>(ciphertext)
            .map_err(|_| InvalidMfaMetadata)?;

        let padding_len = usize::from(*padded.last().ok_or(InvalidMfaMetadata)?);
        let plaintext_len = match padding_len {
            1..=PADDED_PLAINTEXT_LEN => PADDED_PLAINTEXT_LEN - padding_len,
            _ => return Err(InvalidMfaMetadata),
        };
        let (plaintext, padding) = padded.split_at(plaintext_len);
        if padding.iter().any(|&b| usize::from(b) != padding_len) {
            return Err(InvalidMfaMetadata);
        }

        let MfaKeyMetadataPlaintext {
            creation_epoch_time_seconds,
            key_name,
            special_fields: _,
        } = MfaKeyMetadataPlaintext::parse_from_bytes(plaintext).map_err(|_| InvalidMfaMetadata)?;
        // Anything `encrypt` wrote started as a `Timestamp` in milliseconds, so it fits; only a
        // blob produced by something else can overflow here.
        let created_at = creation_epoch_time_seconds
            .checked_mul(1000)
            .map(Timestamp::from_epoch_millis)
            .ok_or(InvalidMfaMetadata)?;
        // Anything `new` rejects can't have been produced by `encrypt`.
        MfaMetadata::new(key_name, created_at).map_err(|_| InvalidMfaMetadata)
    }
}

impl From<[u8; MFA_METADATA_CIPHERTEXT_LEN]> for EncryptedMfaMetadata {
    fn from(value: [u8; MFA_METADATA_CIPHERTEXT_LEN]) -> Self {
        Self(value)
    }
}

impl TryFrom<&[u8]> for EncryptedMfaMetadata {
    type Error = InvalidMfaMetadata;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value.try_into().map(Self).map_err(|_| InvalidMfaMetadata)
    }
}

impl std::fmt::Debug for EncryptedMfaMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedMfaMetadata")
            .finish_non_exhaustive()
    }
}

#[derive(displaydoc::Display, Debug, PartialEq, Eq)]
pub enum InvalidMfaKeyName {
    /// The MFA key name is longer than the maximum of 98 bytes of UTF-8
    TooLong,
    /// The MFA key name contains U+0000
    ContainsNull,
}
impl LogSafeDisplay for InvalidMfaKeyName {}
impl std::error::Error for InvalidMfaKeyName {}

#[derive(displaydoc::Display, Debug, Clone, PartialEq, Eq)]
/// The stored MFA key metadata could not be authenticated or decoded with the provided key
pub struct InvalidMfaMetadata;
impl LogSafeDisplay for InvalidMfaMetadata {}
impl std::error::Error for InvalidMfaMetadata {}

fn mfa_metadata_mac(keys: &MfaMetadataKeys) -> Hmac<Sha256> {
    Hmac::<Sha256>::new_from_slice(&keys.hmac_key).expect("HMAC accepts keys of any length")
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use rand::{RngCore as _, SeedableRng as _};

    use super::*;

    /// The latest `created_at` that can be stored, i.e. the last whole second that still fits in a
    /// [`Timestamp`] when converted back to milliseconds.
    const MAX_STORED_CREATED_AT_EPOCH_SECONDS: u64 = u64::MAX / 1000;

    fn test_rng() -> impl CryptoRng {
        rand_chacha::ChaCha20Rng::seed_from_u64(0)
    }

    fn test_svr_key() -> SvrKey {
        SvrKey::new([0x42; 32])
    }

    fn seconds(s: u64) -> Timestamp {
        Timestamp::from_epoch_millis(s * 1000)
    }

    fn test_metadata() -> MfaMetadata {
        MfaMetadata::new("Andrew's Potato".to_string(), seconds(1_782_484_792)).expect("fits")
    }

    #[test]
    fn round_trip() {
        let encrypted = test_metadata().encrypt(&test_svr_key(), &mut test_rng());
        assert_eq!(
            encrypted.decrypt(&test_svr_key()).expect("valid"),
            test_metadata()
        );
    }

    #[test]
    fn round_trips_name_length_boundaries() {
        for len in [0, MFA_KEY_NAME_MAX_LEN / 2, MFA_KEY_NAME_MAX_LEN] {
            let metadata = MfaMetadata::new("a".repeat(len), seconds(1_782_484_792)).expect("fits");
            let encrypted = metadata.encrypt(&test_svr_key(), &mut test_rng());
            assert_eq!(
                encrypted.decrypt(&test_svr_key()).expect("valid"),
                metadata,
                "for name length {len}"
            );
        }
    }

    #[test]
    fn truncates_to_seconds() {
        let metadata =
            MfaMetadata::new(String::new(), seconds(1_782_484_792).add_millis(999)).expect("fits");
        let encrypted = metadata.encrypt(&test_svr_key(), &mut test_rng());
        assert_eq!(
            encrypted
                .decrypt(&test_svr_key())
                .expect("valid")
                .created_at(),
            seconds(1_782_484_792)
        );
    }

    #[test]
    fn creation_time_extremes_round_trip() {
        for created_at in [
            Timestamp::from_epoch_millis(0),
            seconds(MAX_STORED_CREATED_AT_EPOCH_SECONDS),
            Timestamp::from_epoch_millis(u64::MAX),
        ] {
            let metadata = MfaMetadata::new(String::new(), created_at).expect("no time limit");
            let encrypted = metadata.encrypt(&test_svr_key(), &mut test_rng());
            assert_eq!(
                encrypted
                    .decrypt(&test_svr_key())
                    .expect("valid")
                    .created_at(),
                Timestamp::from_epoch_millis(created_at.epoch_millis() / 1000 * 1000),
                "for {created_at:?}"
            );
        }
    }

    #[test]
    fn rejects_overflowing_creation_time_in_stored_data() {
        let blob_at_limit = encrypt_raw_plaintext(
            &MfaKeyMetadataPlaintext {
                creation_epoch_time_seconds: MAX_STORED_CREATED_AT_EPOCH_SECONDS,
                ..Default::default()
            }
            .write_to_bytes()
            .expect("can serialize"),
        );
        assert_matches!(
            EncryptedMfaMetadata::from(blob_at_limit).decrypt(&test_svr_key()),
            Ok(metadata) if metadata.created_at() == seconds(MAX_STORED_CREATED_AT_EPOCH_SECONDS)
        );

        // A MAC-valid blob whose timestamp doesn't fit in milliseconds is treated as per-entry
        // unreadable metadata rather than wrapping around.
        let blob_past_limit = encrypt_raw_plaintext(
            &MfaKeyMetadataPlaintext {
                creation_epoch_time_seconds: MAX_STORED_CREATED_AT_EPOCH_SECONDS + 1,
                ..Default::default()
            }
            .write_to_bytes()
            .expect("can serialize"),
        );
        assert_matches!(
            EncryptedMfaMetadata::from(blob_past_limit).decrypt(&test_svr_key()),
            Err(InvalidMfaMetadata)
        );
    }

    #[test]
    fn name_validation() {
        // Exactly at the limit still fits, even with the largest timestamp that can be stored (an
        // 8-byte varint; the length limit reserves room for the full 10 bytes).
        let at_limit = MfaMetadata::new(
            "\u{1f499}".repeat(MFA_KEY_NAME_MAX_LEN / 4) + &"a".repeat(MFA_KEY_NAME_MAX_LEN % 4),
            seconds(MAX_STORED_CREATED_AT_EPOCH_SECONDS),
        )
        .expect("fits");
        assert_eq!(at_limit.name().len(), MFA_KEY_NAME_MAX_LEN);
        let encrypted = at_limit.encrypt(&test_svr_key(), &mut test_rng());
        assert_eq!(encrypted.decrypt(&test_svr_key()).expect("valid"), at_limit);

        assert_matches!(
            MfaMetadata::new("a".repeat(MFA_KEY_NAME_MAX_LEN + 1), seconds(0)),
            Err(InvalidMfaKeyName::TooLong)
        );
        assert_matches!(
            MfaMetadata::new("before\0after".to_owned(), seconds(0)),
            Err(InvalidMfaKeyName::ContainsNull)
        );
    }

    #[test]
    fn decrypt_rejects_name_with_null() {
        let blob = encrypt_raw_plaintext(
            &MfaKeyMetadataPlaintext {
                key_name: "before\0after".to_owned(),
                ..Default::default()
            }
            .write_to_bytes()
            .expect("can serialize"),
        );
        assert_matches!(
            EncryptedMfaMetadata::from(blob).decrypt(&test_svr_key()),
            Err(InvalidMfaMetadata)
        );
    }

    #[test]
    fn decrypt_rejects_invalid_utf8_name() {
        // `key_name` (field 2) containing a single invalid UTF-8 byte.
        let blob = encrypt_raw_plaintext(&[0x12, 0x01, 0xff]);
        assert_matches!(
            EncryptedMfaMetadata::from(blob).decrypt(&test_svr_key()),
            Err(InvalidMfaMetadata)
        );
    }

    #[test]
    fn rejects_tampering_and_wrong_key() {
        let encrypted = test_metadata().encrypt(&test_svr_key(), &mut test_rng());

        for i in [
            0,
            IV_LEN,
            IV_LEN + PADDED_PLAINTEXT_LEN - 1,
            MFA_METADATA_CIPHERTEXT_LEN - 1,
        ] {
            let mut tampered = *encrypted.as_bytes();
            tampered[i] ^= 0x01;
            assert_matches!(
                EncryptedMfaMetadata::from(tampered).decrypt(&test_svr_key()),
                Err(InvalidMfaMetadata),
                "tampering at byte {i} should be rejected"
            );
        }
        assert_matches!(
            EncryptedMfaMetadata::try_from(
                &encrypted.as_bytes()[..MFA_METADATA_CIPHERTEXT_LEN - 1]
            ),
            Err(InvalidMfaMetadata)
        );
        assert_matches!(
            encrypted.decrypt(&SvrKey::new([0x43; 32])),
            Err(InvalidMfaMetadata)
        );
    }

    /// Encrypts and MACs `plaintext` (padded like `encrypt` would) under [`test_svr_key`], without
    /// any of `encrypt`'s validation, so tests can build MAC-valid blobs with bad contents.
    fn encrypt_raw_plaintext(plaintext: &[u8]) -> [u8; MFA_METADATA_CIPHERTEXT_LEN] {
        let keys = test_svr_key().derive_mfa_metadata_keys();
        let mut padded = plaintext.to_vec();
        let padding_len = PADDED_PLAINTEXT_LEN - padded.len();
        padded.resize(
            PADDED_PLAINTEXT_LEN,
            u8::try_from(padding_len).expect("fits"),
        );

        let mut blob = [0; MFA_METADATA_CIPHERTEXT_LEN];
        let (iv, rest) = blob
            .split_first_chunk_mut::<IV_LEN>()
            .expect("buffer is longer than the IV");
        let (ciphertext, mac) = rest.split_at_mut(PADDED_PLAINTEXT_LEN);
        test_rng().fill_bytes(iv);
        cbc::Encryptor::<Aes256>::new(&keys.cipher_key.into(), (&*iv).into())
            .encrypt_padded_b2b::<NoPadding>(&padded, ciphertext)
            .expect("valid");
        let mut hmac = mfa_metadata_mac(&keys);
        hmac.update(iv);
        hmac.update(ciphertext);
        mac.copy_from_slice(&hmac.finalize().into_bytes());
        blob
    }

    #[test]
    fn rejects_bad_padding() {
        // A full 112 bytes of "plaintext" leaves no room for padding, so the last byte (0) is read
        // as the padding length, which is never valid.
        let blob = encrypt_raw_plaintext(&[0u8; PADDED_PLAINTEXT_LEN]);
        assert_matches!(
            EncryptedMfaMetadata::from(blob).decrypt(&test_svr_key()),
            Err(InvalidMfaMetadata)
        );
    }
}
