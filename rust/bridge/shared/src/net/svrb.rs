//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_account_keys::{BackupKey, BACKUP_FORWARD_SECRECY_TOKEN_LEN, BACKUP_KEY_LEN};
use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_bridge_types::net::svrb::{StoreArgs, SvrBConnectImpl};
use libsignal_bridge_types::net::{ConnectionManager, TokioAsyncContext};
use libsignal_net::auth::Auth;
use libsignal_net::svrb::{
    restore_backup, store_backup, BackupFileMetadataRef, BackupPreviousSecretDataRef,
    BackupResponse, Error as SvrbError,
};

use crate::net::Environment;
use crate::support::*;
use crate::*;

bridge_handle_fns!(BackupResponse, clone = false);
bridge_handle_fns!(StoreArgs, clone = false);

// Bridging references into async functions doesn't work well. This function
// exists to take references and copy data into a 'static value that can be
// easily passed as a bridged handle to _StoreBackup below.
#[bridge_fn]
fn SecureValueRecoveryForBackups_CreateStoreArgs(
    backup_key: &[u8; BACKUP_KEY_LEN],
    previous_secret_data: &[u8],
    environment: AsType<Environment, u8>,
) -> StoreArgs {
    StoreArgs {
        backup_key: BackupKey(*backup_key),
        previous_secret_data: previous_secret_data.into(),
        environment: environment.into_inner(),
    }
}

#[bridge_io(TokioAsyncContext)]
async fn SecureValueRecoveryForBackups_StoreBackup(
    store: &StoreArgs,
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<BackupResponse, SvrbError> {
    let StoreArgs {
        backup_key,
        previous_secret_data,
        environment: _,
    } = store;

    // Parse previous secret data if provided.
    let previous_data = (!previous_secret_data.is_empty())
        .then_some(&**previous_secret_data)
        .map(BackupPreviousSecretDataRef);

    let svrb = SvrBConnectImpl {
        connection_manager,
        auth: Auth { username, password },
    };
    store_backup(&svrb, backup_key, previous_data).await
}

#[bridge_io(TokioAsyncContext)]
async fn SecureValueRecoveryForBackups_RestoreBackupFromServer(
    backup_key: Box<[u8]>,
    metadata: Box<[u8]>,
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<[u8; BACKUP_FORWARD_SECRECY_TOKEN_LEN], SvrbError> {
    let backup_key: BackupKey = BackupKey(
        backup_key
            .as_ref()
            .try_into()
            .map_err(|_| SvrbError::Protocol("Invalid backup key length".to_string()))?,
    );

    let svrb = SvrBConnectImpl {
        connection_manager,
        auth: Auth { username, password },
    };
    restore_backup(&svrb, &backup_key, BackupFileMetadataRef(&metadata))
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
