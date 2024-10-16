//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Keys used to encrypt a message backup file.

use hkdf::Hkdf;
use libsignal_account_keys::{BackupId, BackupKey};
use sha2::Sha256;

#[derive(Debug)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct MessageBackupKey {
    pub hmac_key: [u8; MessageBackupKey::HMAC_KEY_LEN],
    pub aes_key: [u8; MessageBackupKey::AES_KEY_LEN],
}

/// The data used to encrypt backed-up messages.
///
/// This is derived from a user's [`BackupKey`] and their [`BackupId`]. It is
/// derived as a single key but is logically split into three parts that are
/// used as input to the block cipher during encryption and decryption.
impl MessageBackupKey {
    pub const HMAC_KEY_LEN: usize = 32;
    pub const AES_KEY_LEN: usize = 32;

    pub const LEN: usize = Self::HMAC_KEY_LEN + Self::AES_KEY_LEN;

    /// Derives a `MessageBackupKey` from a user's [`BackupKey`] and [`BackupId`].
    pub fn derive(backup_key: &BackupKey, backup_id: &BackupId) -> Self {
        const INFO: &[u8] = b"20231003_Signal_Backups_EncryptMessageBackup";
        let mut full_bytes = [0; MessageBackupKey::LEN];

        Hkdf::<Sha256>::new(Some(&backup_id.0), &backup_key.0)
            .expand(INFO, &mut full_bytes)
            .expect("valid length");

        // TODO split into arrays instead of slices when the API for that is
        // stabilized. See https://github.com/rust-lang/rust/issues/90091
        let (hmac_key, aes_key) = full_bytes.split_at(Self::HMAC_KEY_LEN);

        Self {
            hmac_key: hmac_key.try_into().expect("correct length"),
            aes_key: aes_key.try_into().expect("correct length"),
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use hex_literal::hex;
    use libsignal_core::Aci;

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
    };

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
