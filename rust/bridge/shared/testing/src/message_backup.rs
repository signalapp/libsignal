//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::*;
use libsignal_bridge_types::io::{AsyncInput, InputStream};
use libsignal_bridge_types::support::*;
use libsignal_bridge_types::*;
use libsignal_message_backup::backup::Purpose;
use libsignal_message_backup::{BackupReader, ReadError, ReadResult};

pub struct ComparableBackup {
    pub backup: libsignal_message_backup::backup::serialize::Backup,
    pub found_unknown_fields: Vec<libsignal_message_backup::FoundUnknownField>,
}

bridge_as_handle!(ComparableBackup);
bridge_handle_fns!(ComparableBackup, clone = false);

#[bridge_fn]
async fn ComparableBackup_ReadUnencrypted(
    stream: &mut dyn InputStream,
    len: u64,
    purpose: AsType<Purpose, u8>,
) -> Result<ComparableBackup, ReadError> {
    let reader = BackupReader::new_unencrypted(AsyncInput::new(stream, len), purpose.into_inner());

    let ReadResult {
        result,
        found_unknown_fields,
    } = reader.read_all().await;

    match result {
        Ok(backup) => Ok(ComparableBackup {
            backup: backup.into(),
            found_unknown_fields,
        }),
        Err(error) => Err(ReadError {
            error,
            found_unknown_fields,
        }),
    }
}

#[bridge_fn]
fn ComparableBackup_GetComparableString(backup: &ComparableBackup) -> String {
    backup.backup.to_string_pretty()
}

#[bridge_fn]
fn ComparableBackup_GetUnknownFields(backup: &ComparableBackup) -> Box<[String]> {
    backup
        .found_unknown_fields
        .iter()
        .map(ToString::to_string)
        .collect()
}
