//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;
use libsignal_bridge_types::message_backup::*;
use libsignal_message_backup::backup::Purpose;
use libsignal_message_backup::frame::LimitedReaderFactory;
use libsignal_message_backup::{BackupReader, ReadResult};
use libsignal_protocol::Aci;

use crate::io::{AsyncInput, InputStream};
use crate::support::*;
use crate::*;

bridge_handle_fns!(MessageBackupKey, clone = false);
bridge_handle_fns!(
    MessageBackupValidationOutcome,
    clone = false,
    jni = false,
    node = false
);

#[bridge_fn]
fn MessageBackupKey_New(master_key: &[u8; 32], aci: Aci) -> MessageBackupKey {
    MessageBackupKey::new(master_key, aci)
}

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
    purpose: AsType<Purpose, u8>,
) -> Result<MessageBackupValidationOutcome, std::io::Error> {
    let streams = [
        AsyncInput::new(first_stream, len),
        AsyncInput::new(second_stream, len),
    ];
    let factory = LimitedReaderFactory::new(streams);

    let (error, found_unknown_fields) =
        match BackupReader::new_encrypted_compressed(&key.0, factory, purpose.into_inner()).await {
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
