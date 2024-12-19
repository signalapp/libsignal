//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::str::FromStr as _;

use ::attest::svr2::lookup_groupid;
use libsignal_account_keys::*;
use libsignal_bridge_macros::*;
use libsignal_core::Aci;
use libsignal_protocol::PrivateKey;

use crate::support::*;
use crate::*;

bridge_handle_fns!(PinHash, node = false);

#[bridge_fn(node = false)]
pub fn PinHash_EncryptionKey(ph: &PinHash) -> [u8; 32] {
    ph.encryption_key
}

#[bridge_fn(node = false)]
pub fn PinHash_AccessKey(ph: &PinHash) -> [u8; 32] {
    ph.access_key
}

#[bridge_fn(node = false)]
pub fn PinHash_FromSalt(pin: &[u8], salt: &[u8; 32]) -> Result<PinHash> {
    PinHash::create(pin, salt)
}

#[bridge_fn(node = false)]
pub fn PinHash_FromUsernameMrenclave(
    pin: &[u8],
    username: String,
    mrenclave: &[u8],
) -> Result<PinHash> {
    PinHash::create(
        pin,
        &PinHash::make_salt(
            &username,
            lookup_groupid(mrenclave).ok_or(Error::MrenclaveLookupError)?,
        ),
    )
}

#[bridge_fn(node = false)]
pub fn Pin_LocalHash(pin: &[u8]) -> Result<String> {
    local_pin_hash(pin)
}

#[bridge_fn(node = false)]
pub fn Pin_VerifyLocalHash(encoded_hash: String, pin: &[u8]) -> Result<bool> {
    verify_local_pin_hash(&encoded_hash, pin)
}

#[bridge_fn]
pub fn AccountEntropyPool_Generate() -> String {
    AccountEntropyPool::generate(&mut rand::thread_rng()).to_string()
}

#[bridge_fn]
pub fn AccountEntropyPool_IsValid(account_entropy: String) -> bool {
    AccountEntropyPool::from_str(&account_entropy).is_ok()
}

#[bridge_fn]
pub fn AccountEntropyPool_DeriveSvrKey(account_entropy: AccountEntropyPool) -> [u8; SVR_KEY_LEN] {
    account_entropy.derive_svr_key()
}

#[bridge_fn]
pub fn AccountEntropyPool_DeriveBackupKey(
    account_entropy: AccountEntropyPool,
) -> [u8; BACKUP_KEY_LEN] {
    let backup_key = BackupKey::derive_from_account_entropy_pool(&account_entropy);
    backup_key.0
}

#[bridge_fn]
pub fn BackupKey_DeriveBackupId(backup_key: &[u8; BACKUP_KEY_LEN], aci: Aci) -> [u8; 16] {
    // The explicit type forces the latest version of the key derivation scheme.
    let backup_key: BackupKey = BackupKey(*backup_key);
    backup_key.derive_backup_id(&aci).0
}

#[bridge_fn]
pub fn BackupKey_DeriveEcKey(backup_key: &[u8; BACKUP_KEY_LEN], aci: Aci) -> PrivateKey {
    // The explicit type forces the latest version of the key derivation scheme.
    let backup_key: BackupKey = BackupKey(*backup_key);
    backup_key.derive_ec_key(&aci)
}

#[bridge_fn]
pub fn BackupKey_DeriveLocalBackupMetadataKey(
    backup_key: &[u8; BACKUP_KEY_LEN],
) -> [u8; LOCAL_BACKUP_METADATA_KEY_LEN] {
    // The explicit type forces the latest version of the key derivation scheme.
    let backup_key: BackupKey = BackupKey(*backup_key);
    backup_key.derive_local_backup_metadata_key()
}

#[bridge_fn]
pub fn BackupKey_DeriveMediaId(
    backup_key: &[u8; BACKUP_KEY_LEN],
    media_name: String,
) -> [u8; MEDIA_ID_LEN] {
    // The explicit type forces the latest version of the key derivation scheme.
    let backup_key: BackupKey = BackupKey(*backup_key);
    backup_key.derive_media_id(&media_name)
}

#[bridge_fn]
pub fn BackupKey_DeriveMediaEncryptionKey(
    backup_key: &[u8; BACKUP_KEY_LEN],
    media_id: &[u8; MEDIA_ID_LEN],
) -> [u8; MEDIA_ENCRYPTION_KEY_LEN] {
    // The explicit type forces the latest version of the key derivation scheme.
    let backup_key: BackupKey = BackupKey(*backup_key);
    backup_key.derive_media_encryption_key_data(media_id)
}

#[bridge_fn]
pub fn BackupKey_DeriveThumbnailTransitEncryptionKey(
    backup_key: &[u8; BACKUP_KEY_LEN],
    media_id: &[u8; MEDIA_ID_LEN],
) -> [u8; MEDIA_ENCRYPTION_KEY_LEN] {
    // The explicit type forces the latest version of the key derivation scheme.
    let backup_key: BackupKey = BackupKey(*backup_key);
    backup_key.derive_thumbnail_transit_encryption_key_data(media_id)
}
