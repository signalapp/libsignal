//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Keys used throughout the backup creation, storage, and recovery process.
//!
//! A client will generate a [`BackupKey`] from their account entropy pool. The client
//! will then derive a [`BackupId`] from this key and their [`Aci`]. This
//! ensures that the `BackupKey` is reconstructible using only state stored in
//! SVR, so that a restorer can reconstruct the `BackupId`.

use hkdf::Hkdf;
use libsignal_core::Aci;
use libsignal_core::curve::PrivateKey;
use partial_default::PartialDefault;
use sha2::Sha256;

use crate::AccountEntropyPool;

const V1: u8 = 1;
const LATEST: u8 = V1;

pub const BACKUP_KEY_LEN: usize = 32;
pub const LOCAL_BACKUP_METADATA_KEY_LEN: usize = 32;
pub const MEDIA_ID_LEN: usize = 15;
pub const BACKUP_FORWARD_SECRECY_TOKEN_LEN: usize = 32;
pub const MEDIA_ENCRYPTION_KEY_LEN: usize = 32 + 32; // HMAC key + AES-CBC key

/// Primary key for backups that is used to derive other keys.
///
/// The type `BackupKey`, leaving the `VERSION` parameter as its default, is used for keys derived
/// from an [`AccountEntropyPool`]. The version will also be inferred if you use
/// [`BackupKey::derive_from_account_entropy_pool`].
#[derive(Debug, PartialDefault, zerocopy::FromBytes, zerocopy::Immutable)]
#[repr(transparent)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct BackupKey<const VERSION: u8 = LATEST>(pub [u8; BACKUP_KEY_LEN]);

impl BackupKey<V1> {
    pub const VERSION: u8 = V1;

    pub fn derive_from_account_entropy_pool(entropy: &AccountEntropyPool) -> Self {
        let mut key = [0; BACKUP_KEY_LEN];
        Hkdf::<Sha256>::new(None, &entropy.entropy_pool)
            .expand(b"20240801_SIGNAL_BACKUP_KEY", &mut key)
            .expect("valid length");
        Self(key)
    }

    pub fn derive_ec_key(&self, aci: &Aci) -> PrivateKey {
        const INFO: &[u8] = b"20241024_SIGNAL_BACKUP_ID_KEYPAIR:";
        let mut private_key_bytes = [0; 32];
        Hkdf::<Sha256>::new(None, &self.0)
            .expand_multi_info(&[INFO, &aci.service_id_binary()], &mut private_key_bytes)
            .expect("valid length");
        PrivateKey::deserialize(&private_key_bytes).expect("correctly generated")
    }

    pub fn derive_local_backup_metadata_key(&self) -> [u8; LOCAL_BACKUP_METADATA_KEY_LEN] {
        const INFO: &[u8] = b"20241011_SIGNAL_LOCAL_BACKUP_METADATA_KEY";
        let mut bytes = [0; LOCAL_BACKUP_METADATA_KEY_LEN];
        Hkdf::<Sha256>::new(None, &self.0)
            .expand(INFO, &mut bytes)
            .expect("valid length");
        bytes
    }

    pub fn derive_media_id(&self, media_name: &str) -> [u8; MEDIA_ID_LEN] {
        const INFO: &[u8] = b"20241007_SIGNAL_BACKUP_MEDIA_ID:";
        let mut bytes = [0; MEDIA_ID_LEN];
        Hkdf::<Sha256>::new(None, &self.0)
            .expand_multi_info(&[INFO, media_name.as_bytes()], &mut bytes)
            .expect("valid length");
        bytes
    }

    pub fn derive_media_encryption_key_data(
        &self,
        media_id: &[u8; MEDIA_ID_LEN],
    ) -> [u8; MEDIA_ENCRYPTION_KEY_LEN] {
        const INFO: &[u8] = b"20241007_SIGNAL_BACKUP_ENCRYPT_MEDIA:";
        let mut bytes = [0; MEDIA_ENCRYPTION_KEY_LEN];
        Hkdf::<Sha256>::new(None, &self.0)
            .expand_multi_info(&[INFO, media_id], &mut bytes)
            .expect("valid length");
        bytes
    }

    pub fn derive_thumbnail_transit_encryption_key_data(
        &self,
        media_id: &[u8; MEDIA_ID_LEN],
    ) -> [u8; MEDIA_ENCRYPTION_KEY_LEN] {
        const INFO: &[u8] = b"20241030_SIGNAL_BACKUP_ENCRYPT_THUMBNAIL:";
        let mut bytes = [0; MEDIA_ENCRYPTION_KEY_LEN];
        Hkdf::<Sha256>::new(None, &self.0)
            .expand_multi_info(&[INFO, media_id], &mut bytes)
            .expect("valid length");
        bytes
    }
}

impl<'a> From<&'a [u8; BACKUP_KEY_LEN]> for &'a BackupKey {
    fn from(value: &'a [u8; BACKUP_KEY_LEN]) -> Self {
        zerocopy::transmute_ref!(value)
    }
}

const BACKUP_FORWARD_SECRECY_ENCRYPTION_KEY_CIPHER_KEY_SIZE: usize = 32;
const BACKUP_FORWARD_SECRECY_ENCRYPTION_KEY_HMAC_KEY_SIZE: usize = 32;

pub struct BackupForwardSecrecyPassword(pub [u8; 32]);
pub struct BackupForwardSecrecyEncryptionKey {
    pub cipher_key: [u8; BACKUP_FORWARD_SECRECY_ENCRYPTION_KEY_CIPHER_KEY_SIZE],
    pub hmac_key: [u8; BACKUP_FORWARD_SECRECY_ENCRYPTION_KEY_HMAC_KEY_SIZE],
}

impl<const VERSION: u8> BackupKey<VERSION> {
    /// Derives a backup ID consistently with how this backup key was created.
    pub fn derive_backup_id(&self, aci: &Aci) -> BackupId {
        let mut bytes = [0; BackupId::LEN];

        // We include both implementations in one function so that they can share the name
        // "derive_backup_id". (This can also be accomplished using traits, but that's overkill
        // here; monomorphization should result in this being compiled as two separate functions
        // anyway.)
        match VERSION {
            V1 => {
                // If this key was derived from an account entropy pool, use the current ID
                // generation scheme.
                const INFO: &[u8] = b"20241024_SIGNAL_BACKUP_ID:";

                Hkdf::<Sha256>::new(None, &self.0)
                    .expand_multi_info(&[INFO, &aci.service_id_binary()], &mut bytes)
                    .expect("valid length");
            }
            _ => panic!("not a valid backup ID version: {VERSION}"),
        }
        BackupId(bytes)
    }

    /// Derives a backup forward secrecy token password from a backup ID and
    /// associated password-specific salt.  This password is meant to protect
    /// a forward secrecy token within secure storage media.
    pub fn derive_forward_secrecy_password(&self, salt: &[u8]) -> BackupForwardSecrecyPassword {
        let mut bytes = [0; 32];
        const INFO: &[u8] = b"Signal Message Backup 20250627:SVR PIN";
        Hkdf::<Sha256>::new(Some(salt), &self.0)
            .expand(INFO, &mut bytes)
            .expect("valid length");
        BackupForwardSecrecyPassword(bytes)
    }
    /// Derives all values necessary to encrypt a forward secrecy token based
    /// on a backup ID and associated encryption-specific salt.
    pub fn derive_forward_secrecy_encryption_key(
        &self,
        salt: &[u8],
    ) -> BackupForwardSecrecyEncryptionKey {
        let mut bytes = [0u8; BACKUP_FORWARD_SECRECY_ENCRYPTION_KEY_CIPHER_KEY_SIZE
            + BACKUP_FORWARD_SECRECY_ENCRYPTION_KEY_HMAC_KEY_SIZE];
        const INFO: &[u8] =
            b"Signal Message Backup 20250627:BackupForwardSecrecyToken Encryption Key";
        Hkdf::<Sha256>::new(Some(salt), &self.0)
            .expand(INFO, &mut bytes)
            .expect("valid length");
        BackupForwardSecrecyEncryptionKey {
            cipher_key: bytes[..BACKUP_FORWARD_SECRECY_ENCRYPTION_KEY_CIPHER_KEY_SIZE]
                .try_into()
                .expect("should have enough bytes"),
            hmac_key: bytes[BACKUP_FORWARD_SECRECY_ENCRYPTION_KEY_CIPHER_KEY_SIZE..]
                [..BACKUP_FORWARD_SECRECY_ENCRYPTION_KEY_HMAC_KEY_SIZE]
                .try_into()
                .expect("should have enough bytes"),
        }
    }
}

/// The per-account key used to store backups.
///
/// This is derived from a user's [`BackupId`] along with their [`Aci`].
#[derive(Debug, Clone, Copy, PartialDefault)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct BackupId(pub [u8; BackupId::LEN]);

impl BackupId {
    pub const LEN: usize = 16;
}

/// An additional token stored in a secure enclave to provide forward secrecy
/// for backups.
#[derive(Debug, Clone, Copy, PartialDefault)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct BackupForwardSecrecyToken(pub [u8; BACKUP_FORWARD_SECRECY_TOKEN_LEN]);

#[cfg(test)]
pub(crate) mod test {
    use const_str::hex;

    use super::*;

    // Generated from AccountEntropyPool::generate.
    const FAKE_ACCOUNT_ENTROPY_POOL: AccountEntropyPool = AccountEntropyPool {
        entropy_pool: *b"dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l",
    };
    const FAKE_ACI: Aci = Aci::from_uuid_bytes(hex!("659aa5f4a28dfcc11ea1b997537a3d95"));

    #[test]
    fn backup_key_known_from_account_entropy() {
        let b = BackupKey::derive_from_account_entropy_pool(&FAKE_ACCOUNT_ENTROPY_POOL);

        const EXPECTED_KEY_BYTES: [u8; BACKUP_KEY_LEN] =
            hex!("ea26a2ddb5dba5ef9e34e1b8dea1f5ae7f255306a6d2d883e542306eaa9fe985");

        assert_eq!(b, BackupKey(EXPECTED_KEY_BYTES), "got {b:02x?}");
    }

    #[test]
    fn backup_id_known_from_account_entropy() {
        let key = BackupKey::derive_from_account_entropy_pool(&FAKE_ACCOUNT_ENTROPY_POOL);
        let id = key.derive_backup_id(&FAKE_ACI);

        const EXPECTED_ID_BYTES: [u8; BackupId::LEN] = hex!("8a624fbc45379043f39f1391cddc5fe8");
        assert_eq!(id, BackupId(EXPECTED_ID_BYTES), "got {id:02x?}");
    }
}
