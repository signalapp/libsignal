//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures_util::io::BufReader;
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
fn MessageBackupKey_FromMasterKey(master_key: &[u8; 32], aci: Aci) -> MessageBackupKey {
    MessageBackupKey::from_master_key(master_key, aci)
}

#[bridge_fn]
fn MessageBackupKey_FromAccountEntropyPool(account_entropy: String, aci: Aci) -> MessageBackupKey {
    MessageBackupKey::from_account_entropy_pool(&account_entropy, aci)
}

#[bridge_fn]
fn MessageBackupKey_FromBackupKeyAndBackupId(
    backup_key: &[u8; 32],
    backup_id: &[u8; 16],
) -> MessageBackupKey {
    MessageBackupKey::from_backup_key_and_backup_id(backup_key, backup_id)
}

#[bridge_fn(ffi = false, node = false)]
fn MessageBackupKey_FromParts(hmac_key: &[u8; 32], aes_key: &[u8; 32]) -> MessageBackupKey {
    MessageBackupKey::from_parts(*hmac_key, *aes_key)
}

#[bridge_fn]
fn MessageBackupKey_GetHmacKey(key: &MessageBackupKey) -> [u8; 32] {
    key.0.hmac_key
}

#[bridge_fn]
fn MessageBackupKey_GetAesKey(key: &MessageBackupKey) -> [u8; 32] {
    key.0.aes_key
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
        // The first stream is read in bulk, so buffering doesn't gain us anything.
        BufReader::with_capacity(0, AsyncInput::new(first_stream, len)),
        BufReader::new(AsyncInput::new(second_stream, len)),
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
