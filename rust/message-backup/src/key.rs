//
// Copyright (C) 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Keys used to encrypt a message backup file.

use hkdf::Hkdf;
use libsignal_account_keys::{BackupForwardSecrecyToken, BackupId, BackupKey};
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
    pub fn derive<const VERSION: u8>(
        backup_key: &BackupKey<VERSION>,
        backup_id: &BackupId,
        backup_nonce: Option<&BackupForwardSecrecyToken>,
    ) -> Self {
        let mut full_bytes = [0; MessageBackupKey::LEN];

        // See [`BackupKey::derive_backup_id`] for an explanation of this pattern.
        match VERSION {
            // Disable inference by using explicit type syntax <>, giving us the latest version.
            <BackupKey>::VERSION => {
                const OLD_DST: &[u8] = b"20241007_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:";
                const NEW_DST: &[u8] = b"20250708_SIGNAL_BACKUP_ENCRYPT_MESSAGE_BACKUP:";

                let (salt, dst) = match backup_nonce {
                    Some(nonce) => (Some(&nonce.0[..]), NEW_DST),
                    None => (None, OLD_DST),
                };

                Hkdf::<Sha256>::new(salt, &backup_key.0)
                    .expand_multi_info(&[dst, &backup_id.0], &mut full_bytes)
                    .expect("valid length");
            }
            _ => unreachable!("invalid backup key version"),
        }

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
    use const_str::hex;
    use libsignal_core::Aci;

    use super::*;

    // Generated from AccountEntropyPool::generate.
    const FAKE_ACCOUNT_ENTROPY_POOL: &str =
        "dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l";
    const FAKE_ACI: Aci = Aci::from_uuid_bytes(hex!("659aa5f4a28dfcc11ea1b997537a3d95"));
    const FAKE_BACKUP_FORWARD_SECRECY_TOKEN: BackupForwardSecrecyToken = BackupForwardSecrecyToken(
        hex!("69207061737320746865206b6e69666520746f207468652061786f6c6f746c21"),
    );

    /// Valid, random key for testing.
    ///
    /// This is derived from [`FAKE_ACCOUNT_ENTROPY_POOL`], [`FAKE_ACI`], and [`FAKE_BACKUP_FORWARD_SECRECY_TOKEN`] (verified in
    /// [`message_backup_key_known`] below).
    pub(crate) const FAKE_MESSAGE_BACKUP_KEY: MessageBackupKey = MessageBackupKey {
        hmac_key: hex!("20e6ab57b87e051f3e695e953cf8a261dd307e4f92ae2921673f1d397e07887b"),
        aes_key: hex!("602af6ecfc09d695a8d58da9f18225e967979c5e03543ca0224a03cca3d9735e"),
    };

    pub(crate) const FAKE_MESSAGE_BACKUP_KEY_LEGACY: MessageBackupKey = MessageBackupKey {
        hmac_key: hex!("f425e22a607c529717e1e1b29f9fe139f9d1c7e7d01e371c7753c544a3026649"),
        aes_key: hex!("e143f4ad5668d8bfed2f88562f0693f53bda2c0e55c9d71730f30e24695fd6df"),
    };

    #[test]
    fn message_backup_key_known() {
        let key = BackupKey::derive_from_account_entropy_pool(
            &FAKE_ACCOUNT_ENTROPY_POOL.parse().expect("valid"),
        );
        let id = key.derive_backup_id(&FAKE_ACI);
        let message_backup_key =
            MessageBackupKey::derive(&key, &id, Some(&FAKE_BACKUP_FORWARD_SECRECY_TOKEN));

        assert_eq!(
            message_backup_key, FAKE_MESSAGE_BACKUP_KEY,
            "got {message_backup_key:02x?}"
        );
    }

    #[test]
    fn message_backup_key_legacy() {
        let key = BackupKey::derive_from_account_entropy_pool(
            &FAKE_ACCOUNT_ENTROPY_POOL.parse().expect("valid"),
        );
        let id = key.derive_backup_id(&FAKE_ACI);
        let message_backup_key = MessageBackupKey::derive(&key, &id, None);

        assert_eq!(
            message_backup_key, FAKE_MESSAGE_BACKUP_KEY_LEGACY,
            "got {message_backup_key:02x?}"
        );
    }
}
