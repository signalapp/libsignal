//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_message_backup::frame::ValidationError as FrameValidationError;
use libsignal_message_backup::key::{BackupKey, MessageBackupKey as MessageBackupKeyInner};
use libsignal_message_backup::parse::ParseError;
use libsignal_message_backup::{Error, FoundUnknownField};
use libsignal_protocol::Aci;

use crate::*;

pub struct MessageBackupKey(pub MessageBackupKeyInner);

impl MessageBackupKey {
    pub fn new(master_key: &[u8; 32], aci: Aci) -> Self {
        let backup_key = BackupKey::derive_from_master_key(master_key);
        let backup_id = backup_key.derive_backup_id(&aci);
        Self(MessageBackupKeyInner::derive(&backup_key, &backup_id))
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
