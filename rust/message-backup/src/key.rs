//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Keys used throughout the backup creation, storage, and recovery process.
//!
//! A client will generate a [`BackupKey`] from their master key. The client
//! will then derive a [`BackupId`] from this key and their [`Aci`]. This
//! ensures that the `BackupKey` is reconstructible using only state stored in
//! SVR, so that a restorer can reconstruct the `BackupId`.

use hkdf::Hkdf;
use libsignal_protocol::Aci;
use sha2::Sha256;

/// Primary key for backups that is used to derive other keys.
#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct BackupKey([u8; BackupKey::LEN]);

impl BackupKey {
    pub const LEN: usize = 32;
    pub const MASTER_KEY_LEN: usize = 32;

    /// Derive a `BackupKey` from the provided master key.
    pub fn derive_from_master_key(master_key: &[u8; Self::MASTER_KEY_LEN]) -> Self {
        const INFO: &[u8] = b"20231003_Signal_Backups_GenerateBackupKey";

        let mut key = [0; Self::LEN];

        Hkdf::<Sha256>::new(
            None, // Empty salt
            master_key,
        )
        .expand(INFO, &mut key)
        .expect("valid length");

        Self(key)
    }

    /// Derive the [`BackupId`] from a user's `BackupKey` and [`Aci`].
    pub fn derive_backup_id(&self, aci: &Aci) -> BackupId {
        const INFO: &[u8] = b"20231003_Signal_Backups_GenerateBackupId";
        let mut bytes = [0; BackupId::LEN];

        Hkdf::<Sha256>::new(Some(&aci.service_id_binary()), &self.0)
            .expand(INFO, &mut bytes)
            .expect("valid length");

        BackupId(bytes)
    }
}

/// The per-account key used to store backups.
///
/// This is derived from a user's [`BackupId`] along with their [`Aci`].
#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct BackupId([u8; BackupId::LEN]);

impl BackupId {
    pub const LEN: usize = 16;
}

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct MessageBackupKey {
    pub hmac_key: [u8; MessageBackupKey::HMAC_KEY_LEN],
    pub aes_key: [u8; MessageBackupKey::AES_KEY_LEN],
    pub iv: [u8; MessageBackupKey::IV_LEN],
}

/// The data used to encrypt backed-up messages.
///
/// This is derived from a user's [`BackupKey`] and their [`BackupId`]. It is
/// derived as a single key but is logically split into three parts that are
/// used as input to the block cipher during encryption and decryption.
impl MessageBackupKey {
    pub const HMAC_KEY_LEN: usize = 32;
    pub const AES_KEY_LEN: usize = 32;
    pub const IV_LEN: usize = 16;

    pub const LEN: usize = Self::HMAC_KEY_LEN + Self::AES_KEY_LEN + Self::IV_LEN;

    /// Derives a `MessageBackupKey` from a user's [`BackupKey`] and [`BackupId`].
    pub fn derive(backup_key: &BackupKey, backup_id: &BackupId) -> Self {
        const INFO: &[u8] = b"20231003_Signal_Backups_EncryptMessageBackup";
        let mut full_bytes = [0; MessageBackupKey::LEN];

        Hkdf::<Sha256>::new(Some(&backup_id.0), &backup_key.0)
            .expand(INFO, &mut full_bytes)
            .expect("valid length");

        // TODO split into arrays instead of slices when that is stabilized.
        let (hmac_key, tail) = full_bytes.split_at(Self::HMAC_KEY_LEN);
        let (aes_key, iv) = tail.split_at(Self::AES_KEY_LEN);

        Self {
            hmac_key: hmac_key.try_into().expect("correct length"),
            aes_key: aes_key.try_into().expect("correct length"),
            iv: iv.try_into().expect("correct length"),
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use hex_literal::hex;

    use super::*;

    const FAKE_MASTER_KEY: [u8; 32] =
        hex!("6c25a28f50f61f7ab94958cffc64164d897dab61457cceb0bb6126ca54c38cc4");
    const FAKE_ACI: Aci = Aci::from_uuid_bytes(hex!("659aa5f4a28dfcc11ea1b997537a3d95"));

    /// Valid, random key for testing.
    ///
    /// This is derived from [`FAKE_MASTER_KEY`] and [`FAKE_ACI`] (verified in
    /// [`message_backup_key_known`] below).
    pub(crate) const FAKE_MESSAGE_BACKUP_KEY: MessageBackupKey = MessageBackupKey {
        hmac_key: hex!("7624d47e91d7f4de5eae5f00a1662984e3e81177473a3fab60320e4b9c6d6676"),
        aes_key: hex!("44ea4f8a6e9a404c1f98a2c0b18172c9b2171f02137571a8272d671021bfff3f"),
        iv: hex!("55a3d64f031ee3a35271a12e18077652"),
    };

    #[test]
    fn backup_key_known() {
        let b = BackupKey::derive_from_master_key(&FAKE_MASTER_KEY);

        const EXPECTED_KEY_BYTES: [u8; BackupKey::LEN] =
            hex!("7cc5ad13a6d43ec374ae95d83dcfb86c9314d449dc926a036b38bb55fe236142");

        assert_eq!(b, BackupKey(EXPECTED_KEY_BYTES), "got {b:02x?}");
    }

    #[test]
    fn backup_id_known() {
        let key = BackupKey::derive_from_master_key(&FAKE_MASTER_KEY);
        let id = key.derive_backup_id(&FAKE_ACI);

        const EXPECTED_ID_BYTES: [u8; BackupId::LEN] = hex!("5ccec70e2a141866baecd5e271413b02");
        assert_eq!(id, BackupId(EXPECTED_ID_BYTES), "got {id:02x?}");
    }

    #[test]
    fn message_backup_key_known() {
        let key = BackupKey::derive_from_master_key(&FAKE_MASTER_KEY);
        let id = key.derive_backup_id(&FAKE_ACI);
        let message_backup_key = MessageBackupKey::derive(&key, &id);

        assert_eq!(
            message_backup_key, FAKE_MESSAGE_BACKUP_KEY,
            "got {message_backup_key:02x?}"
        );
    }
}
