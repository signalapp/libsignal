//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[cfg(any(feature = "jni", feature = "ffi"))]
use futures_util::FutureExt as _;
use libsignal_bridge_macros::*;
use libsignal_message_backup::frame::{
    LimitedReaderFactory, ValidationError as FrameValidationError,
};
use libsignal_message_backup::key::{BackupKey, MessageBackupKey as MessageBackupKeyInner};
use libsignal_message_backup::parse::ParseError;
use libsignal_message_backup::{BackupReader, Error, FoundUnknownField, ReadResult};
use libsignal_protocol::Aci;

use crate::io::{AsyncInput, InputStream};
use crate::support::*;
use crate::*;

pub struct MessageBackupKey(#[allow(unused)] MessageBackupKeyInner);

bridge_handle!(MessageBackupKey, clone = false);

#[bridge_fn]
fn MessageBackupKey_New(master_key: &[u8; 32], aci: Aci) -> MessageBackupKey {
    let backup_key = BackupKey::derive_from_master_key(master_key);
    let backup_id = backup_key.derive_backup_id(&aci);
    MessageBackupKey(MessageBackupKeyInner::derive(&backup_key, &backup_id))
}

#[derive(Debug)]
enum MessageBackupValidationError {
    Io(std::io::Error),
    String(String),
}

impl From<Error> for MessageBackupValidationError {
    fn from(value: Error) -> Self {
        match value {
            Error::BackupValidation(e) => Self::String(e.to_string()),
            Error::Parse(ParseError::Io(e)) => Self::Io(e),
            e @ Error::NoFrames
            | e @ Error::InvalidProtobuf(_)
            | e @ Error::Parse(ParseError::Decode(_)) => Self::String(e.to_string()),
        }
    }
}

impl From<FrameValidationError> for MessageBackupValidationError {
    fn from(value: FrameValidationError) -> Self {
        match value {
            FrameValidationError::Io(e) => Self::Io(e),
            e @ (FrameValidationError::TooShort | FrameValidationError::InvalidHmac) => {
                Self::String(e.to_string())
            }
        }
    }
}

pub struct MessageBackupValidationOutcome {
    pub(crate) error_message: Option<String>,
    pub(crate) found_unknown_fields: Vec<FoundUnknownField>,
}
#[cfg(feature = "ffi")]
ffi_bridge_handle!(MessageBackupValidationOutcome, clone = false);

#[bridge_fn(jni = false, node = false)]
fn MessageBackupValidationOutcome_getErrorMessage(
    outcome: &MessageBackupValidationOutcome,
) -> Option<&str> {
    outcome.error_message.as_deref()
}

#[bridge_fn(jni = false, node = false)]
fn MessageBackupValidationOutcome_getUnknownFields(
    outcome: &MessageBackupValidationOutcome,
) -> Box<[String]> {
    outcome
        .found_unknown_fields
        .iter()
        .map(ToString::to_string)
        .collect()
}

#[bridge_fn]
async fn MessageBackupValidator_Validate(
    key: &MessageBackupKey,
    first_stream: &mut dyn InputStream,
    second_stream: &mut dyn InputStream,
    len: u64,
) -> Result<MessageBackupValidationOutcome, std::io::Error> {
    let MessageBackupKey(key) = key;

    let streams = [
        AsyncInput::new(first_stream, len),
        AsyncInput::new(second_stream, len),
    ];
    let factory = LimitedReaderFactory::new(streams);

    let (error, found_unknown_fields) =
        match BackupReader::new_encrypted_compressed(key, factory).await {
            Err(e) => (Some(e.into()), Vec::new()),
            Ok(reader) => {
                let ReadResult {
                    result,
                    found_unknown_fields,
                } = reader.validate_all().await;

                (result.err().map(Into::into), found_unknown_fields)
            }
        };

    let error_message = error
        .map(|m| match m {
            MessageBackupValidationError::Io(io) => Err(io),
            MessageBackupValidationError::String(msg) => Ok(msg),
        })
        .transpose()?;

    Ok(MessageBackupValidationOutcome {
        error_message,
        found_unknown_fields,
    })
}
