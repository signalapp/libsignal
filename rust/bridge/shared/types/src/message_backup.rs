//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_account_keys::{AccountEntropyPool, BackupId, BackupKey, BACKUP_KEY_LEN};
use libsignal_message_backup::frame::ValidationError as FrameValidationError;
use libsignal_message_backup::key::MessageBackupKey as MessageBackupKeyInner;
use libsignal_message_backup::parse::ParseError;
use libsignal_message_backup::{backup, Error, FoundUnknownField};
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

    pub fn from_account_entropy_pool(account_entropy: &AccountEntropyPool, aci: Aci) -> Self {
        let backup_key = BackupKey::derive_from_account_entropy_pool(account_entropy);
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
    pub backup: backup::serialize::Backup,
    pub found_unknown_fields: Vec<FoundUnknownField>,
}

bridge_as_handle!(ComparableBackup);

pub struct OnlineBackupValidator {
    backup: Option<backup::PartialBackup<backup::ValidateOnly>>,
}

impl OnlineBackupValidator {
    pub fn from_backup_info_frame(
        backup_info: &[u8],
        purpose: backup::Purpose,
    ) -> Result<Self, Error> {
        Ok(Self {
            backup: Some(backup::PartialBackup::by_parsing(
                backup_info,
                purpose,
                |_| (),
            )?),
        })
    }

    pub fn get_mut(&mut self) -> &mut backup::PartialBackup<backup::ValidateOnly> {
        self.backup
            .as_mut()
            .expect("OnlineBackupValidator has not yet been finalized")
    }

    pub fn finalize(&mut self) -> Result<(), Error> {
        let partial_backup = self
            .backup
            .take()
            .expect("OnlineBackupValidator has not yet been finalized");
        _ = backup::CompletedBackup::try_from(partial_backup)?;
        Ok(())
    }
}

// This isn't strictly correct; OnlineBackupValidator *does* contain interior mutability.
// However, because it only allows `&mut` access to its state, it can't be an issue in practice.
// (`bridge_fn` doesn't know that and so it expects RefUnwindSafe simply for being passed as a pointer.)
impl std::panic::RefUnwindSafe for OnlineBackupValidator {}
static_assertions::assert_impl_all!(OnlineBackupValidator: std::panic::UnwindSafe);

bridge_as_handle!(OnlineBackupValidator, mut = true);

impl Drop for OnlineBackupValidator {
    fn drop(&mut self) {
        if self.backup.is_some() {
            log::warn!("OnlineBackupValidator is dropped without calling finalize");
        }
    }
}
