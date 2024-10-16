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
use libsignal_core::Aci;
use partial_default::PartialDefault;
use sha2::Sha256;

/// Primary key for backups that is used to derive other keys.
#[derive(Debug, PartialDefault)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(transparent)
)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub struct BackupKey(pub [u8; BackupKey::LEN]);

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

    const FAKE_MASTER_KEY: [u8; 32] =
        hex!("6c25a28f50f61f7ab94958cffc64164d897dab61457cceb0bb6126ca54c38cc4");
    const FAKE_ACI: Aci = Aci::from_uuid_bytes(hex!("659aa5f4a28dfcc11ea1b997537a3d95"));

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
}
