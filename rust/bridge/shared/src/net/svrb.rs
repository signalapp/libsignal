//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_account_keys::{BackupKey, BACKUP_FORWARD_SECRECY_TOKEN_LEN};
use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_bridge_types::net::svrb::SvrBConnectImpl;
use libsignal_bridge_types::net::{ConnectionManager, TokioAsyncContext};
use libsignal_net::auth::Auth;
use libsignal_net::svrb::{
    restore_backup, store_backup, BackupFileMetadataRef, BackupPreviousSecretDataRef,
    BackupResponse, Error as SvrbError,
};

use crate::support::*;
use crate::*;

bridge_handle_fns!(BackupResponse, clone = false);

#[bridge_io(TokioAsyncContext)]
async fn SecureValueRecoveryForBackups_StoreBackup(
    backup_key: &BackupKey,
    previous_secret_data: Box<[u8]>,
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<BackupResponse, SvrbError> {
    // Parse previous secret data if provided.
    let previous_data = (!previous_secret_data.is_empty())
        .then_some(&*previous_secret_data)
        .map(BackupPreviousSecretDataRef);

    let svrb = SvrBConnectImpl {
        connection_manager,
        auth: Auth { username, password },
    };
    store_backup(&svrb, backup_key, previous_data).await
}

#[bridge_io(TokioAsyncContext)]
async fn SecureValueRecoveryForBackups_RestoreBackupFromServer(
    backup_key: &BackupKey,
    metadata: Box<[u8]>,
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<[u8; BACKUP_FORWARD_SECRECY_TOKEN_LEN], SvrbError> {
    let svrb = SvrBConnectImpl {
        connection_manager,
        auth: Auth { username, password },
    };
    restore_backup(&svrb, backup_key, BackupFileMetadataRef(&metadata))
        .await
        .map(|token| token.0)
}

#[bridge_fn]
fn BackupResponse_GetForwardSecrecyToken(
    response: &BackupResponse,
) -> Result<[u8; BACKUP_FORWARD_SECRECY_TOKEN_LEN], SvrbError> {
    Ok(response.forward_secrecy_token.0)
}

#[bridge_fn]
fn BackupResponse_GetOpaqueMetadata(response: &BackupResponse) -> Result<&[u8], SvrbError> {
    Ok(&response.metadata.0)
}

#[bridge_fn]
fn BackupResponse_GetNextBackupSecretData(response: &BackupResponse) -> &[u8] {
    &response.next_backup_data.0
}
