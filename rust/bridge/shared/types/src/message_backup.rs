//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::str::FromStr as _;

use libsignal_account_keys::{AccountEntropyPool, BackupId, BackupKey, BACKUP_KEY_LEN};
use libsignal_message_backup::frame::ValidationError as FrameValidationError;
use libsignal_message_backup::key::MessageBackupKey as MessageBackupKeyInner;
use libsignal_message_backup::parse::ParseError;
use libsignal_message_backup::{Error, FoundUnknownField};
use libsignal_protocol::Aci;

use crate::*;

pub struct MessageBackupKey(pub MessageBackupKeyInner);

impl MessageBackupKey {
    pub fn from_master_key(master_key: &[u8; 32], aci: Aci) -> Self {
        #[allow(deprecated)]
        let backup_key = BackupKey::derive_from_master_key(master_key);
        let backup_id = backup_key.derive_backup_id(&aci);
        Self(MessageBackupKeyInner::derive(&backup_key, &backup_id))
    }

    pub fn from_account_entropy_pool(account_entropy: &str, aci: Aci) -> Self {
        let entropy = AccountEntropyPool::from_str(account_entropy)
            .expect("should only pass validated entropy pool here");
        let backup_key = BackupKey::derive_from_account_entropy_pool(&entropy);
        let backup_id = backup_key.derive_backup_id(&aci);
        Self(MessageBackupKeyInner::derive(&backup_key, &backup_id))
    }

    /// Used when reading from a local backup, where we might not have the ACI.
    ///
    /// We could take an account entropy pool here as well, but the backup ID is protected by a key
    /// derived from the main backup key, so the caller will have already done the work to derive it
    /// anyway.
    pub fn from_backup_key_and_backup_id(
        backup_key: &[u8; BACKUP_KEY_LEN],
        backup_id: &[u8; BackupId::LEN],
    ) -> Self {
        // The explicit type forces the latest version of the key derivation scheme.
        let backup_key: BackupKey = BackupKey(*backup_key);
        let backup_id = BackupId(*backup_id);
        Self(MessageBackupKeyInner::derive(&backup_key, &backup_id))
    }

    pub fn from_parts(
        hmac_key: [u8; MessageBackupKeyInner::HMAC_KEY_LEN],
        aes_key: [u8; MessageBackupKeyInner::AES_KEY_LEN],
    ) -> Self {
        Self(MessageBackupKeyInner { hmac_key, aes_key })
    }
}

bridge_as_handle!(MessageBackupKey);

#[derive(Debug)]
pub enum MessageBackupValidationError {
    Io(std::io::Error),
    String(String),
}

impl From<Error> for MessageBackupValidationError {
    fn from(value: Error) -> Self {
        match value {
            Error::BackupValidation(e) => Self::String(e.to_string()),
            Error::BackupCompletion(e) => Self::String(e.to_string()),
            Error::Parse(ParseError::Io(e)) => Self::Io(e),
            e @ Error::NoFrames
            | e @ Error::InvalidProtobuf(_)
            | e @ Error::HmacMismatch(_)
            | e @ Error::Parse(ParseError::Decode(_)) => Self::String(e.to_string()),
        }
    }
}

impl From<FrameValidationError> for MessageBackupValidationError {
    fn from(value: FrameValidationError) -> Self {
        match value {
            FrameValidationError::Io(e) => Self::Io(e),
            e @ (FrameValidationError::TooShort | FrameValidationError::InvalidHmac(_)) => {
                Self::String(e.to_string())
            }
        }
    }
}

pub struct MessageBackupValidationOutcome {
    pub error_message: Option<String>,
    pub found_unknown_fields: Vec<FoundUnknownField>,
}
bridge_as_handle!(MessageBackupValidationOutcome, jni = false, node = false);

pub struct ComparableBackup {
    pub backup: libsignal_message_backup::backup::serialize::Backup,
    pub found_unknown_fields: Vec<FoundUnknownField>,
}

bridge_as_handle!(ComparableBackup);
