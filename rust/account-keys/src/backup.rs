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
use libsignal_core::curve::PrivateKey;
use libsignal_core::Aci;
use partial_default::PartialDefault;
use sha2::Sha256;

use crate::{AccountEntropyPool, SVR_KEY_LEN};

const V0: u8 = 0;
const V1: u8 = 1;
const LATEST: u8 = V1;

pub const BACKUP_KEY_LEN: usize = 32;
pub const LOCAL_BACKUP_METADATA_KEY_LEN: usize = 32;
pub const MEDIA_ID_LEN: usize = 15;
pub const MEDIA_ENCRYPTION_KEY_LEN: usize = 32 + 32; // HMAC key + AES-CBC key

/// Primary key for backups that is used to derive other keys.
///
/// The type `BackupKey`, leaving the `VERSION` parameter as its default, is used for keys derived
/// from an [`AccountEntropyPool`]. Use [`BackupKeyV0`] if you want to derive keys using the "master
/// key" scheme. (This will eventually go away.) The version will also be inferred if you use
/// [`BackupKey::derive_from_master_key`] or [`BackupKey::derive_from_account_entropy_pool`].
#[derive(Debug, PartialDefault)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct BackupKey<const VERSION: u8 = LATEST>(pub [u8; BACKUP_KEY_LEN]);

/// A BackupKey that uses legacy derivations of its derived keys.
pub type BackupKeyV0 = BackupKey<V0>;

impl BackupKey<V0> {
    pub const VERSION: u8 = V0;
    pub const MASTER_KEY_LEN: usize = SVR_KEY_LEN;

    /// Derive a `BackupKey` from the provided master key.
    #[deprecated = "Use AccountEntropyPool instead"]
    pub fn derive_from_master_key(master_key: &[u8; Self::MASTER_KEY_LEN]) -> Self {
        const INFO: &[u8] = b"20231003_Signal_Backups_GenerateBackupKey";

        let mut key = [0; BACKUP_KEY_LEN];

        Hkdf::<Sha256>::new(
            None, // Empty salt
            master_key,
        )
        .expand(INFO, &mut key)
        .expect("valid length");

        Self(key)
    }
}

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

impl<const VERSION: u8> BackupKey<VERSION> {
    /// Derives a backup ID consistently with how this backup key was created.
    pub fn derive_backup_id(&self, aci: &Aci) -> BackupId {
        let mut bytes = [0; BackupId::LEN];

        // We include both implementations in one function so that they can share the name
        // "derive_backup_id". (This can also be accomplished using traits, but that's overkill
        // here; monomorphization should result in this being compiled as two separate functions
        // anyway.)
        match VERSION {
            V0 => {
                // If this key was derived from a "master key", use the old ID generation scheme.
                const INFO: &[u8] = b"20231003_Signal_Backups_GenerateBackupId";

                Hkdf::<Sha256>::new(Some(&aci.service_id_binary()), &self.0)
                    .expand(INFO, &mut bytes)
                    .expect("valid length");
            }
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

#[cfg(test)]
pub(crate) mod test {
    use hex_literal::hex;

    use super::*;

    // Generated from AccountEntropyPool::generate.
    const FAKE_ACCOUNT_ENTROPY_POOL: AccountEntropyPool = AccountEntropyPool {
        entropy_pool: *b"dtjs858asj6tv0jzsqrsmj0ubp335pisj98e9ssnss8myoc08drhtcktyawvx45l",
    };
    const FAKE_MASTER_KEY: [u8; 32] =
        hex!("6c25a28f50f61f7ab94958cffc64164d897dab61457cceb0bb6126ca54c38cc4");
    const FAKE_ACI: Aci = Aci::from_uuid_bytes(hex!("659aa5f4a28dfcc11ea1b997537a3d95"));

    #[test]
    fn backup_key_known_from_master_key() {
        #[allow(deprecated)]
        let b = BackupKey::derive_from_master_key(&FAKE_MASTER_KEY);

        const EXPECTED_KEY_BYTES: [u8; BACKUP_KEY_LEN] =
            hex!("7cc5ad13a6d43ec374ae95d83dcfb86c9314d449dc926a036b38bb55fe236142");

        assert_eq!(b, BackupKey(EXPECTED_KEY_BYTES), "got {b:02x?}");
    }

    #[test]
    fn backup_id_known_from_master_key() {
        #[allow(deprecated)]
        let key = BackupKey::derive_from_master_key(&FAKE_MASTER_KEY);
        let id = key.derive_backup_id(&FAKE_ACI);

        const EXPECTED_ID_BYTES: [u8; BackupId::LEN] = hex!("5ccec70e2a141866baecd5e271413b02");
        assert_eq!(id, BackupId(EXPECTED_ID_BYTES), "got {id:02x?}");
    }

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
