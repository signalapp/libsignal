//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_account_keys::{BACKUP_FORWARD_SECRECY_TOKEN_LEN, BackupKey};
use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_bridge_types::net::svrb::SvrBConnectImpl;
use libsignal_bridge_types::net::{ConnectionManager, Environment, TokioAsyncContext};
use libsignal_net::auth::Auth;
use libsignal_net::svrb::{
    BackupFileMetadataRef, BackupPreviousSecretDataRef, BackupRestoreResponse, BackupStoreResponse,
    Error as SvrbError, create_new_backup_chain, remove_backup, restore_backup, store_backup,
};

use crate::support::*;
use crate::*;

bridge_handle_fns!(BackupStoreResponse, clone = false);
bridge_handle_fns!(BackupRestoreResponse, clone = false);

#[bridge_fn]
fn SecureValueRecoveryForBackups_CreateNewBackupChain(
    environment: AsType<Environment, u8>,
    backup_key: &BackupKey,
) -> Vec<u8> {
    create_new_backup_chain(&environment.env().svr_b, backup_key).0
}

#[bridge_io(TokioAsyncContext)]
async fn SecureValueRecoveryForBackups_StoreBackup(
    backup_key: &BackupKey,
    previous_secret_data: Box<[u8]>,
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<BackupStoreResponse, SvrbError> {
    let auth = Auth { username, password };
    let current_svrb = connection_manager
        .env()
        .svr_b
        .current()
        .map(|e| SvrBConnectImpl {
            connection_manager,
            endpoint: e,
            auth: &auth,
        })
        .collect::<Vec<_>>();
    let previous_svrb = connection_manager
        .env()
        .svr_b
        .previous()
        .map(|e| SvrBConnectImpl {
            connection_manager,
            endpoint: e,
            auth: &auth,
        })
        .collect::<Vec<_>>();

    let previous_data = BackupPreviousSecretDataRef(&previous_secret_data);
    store_backup(&current_svrb, &previous_svrb, backup_key, previous_data).await
}

#[bridge_io(TokioAsyncContext)]
async fn SecureValueRecoveryForBackups_RestoreBackupFromServer(
    backup_key: &BackupKey,
    metadata: Box<[u8]>,
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<BackupRestoreResponse, SvrbError> {
    let auth = Auth { username, password };
    let all_svrbs = connection_manager
        .env()
        .svr_b
        .current_and_previous()
        .map(|e| SvrBConnectImpl {
            connection_manager,
            endpoint: e,
            auth: &auth,
        })
        .collect::<Vec<_>>();
    restore_backup(&all_svrbs, backup_key, BackupFileMetadataRef(&metadata)).await
}

#[bridge_io(TokioAsyncContext)]
async fn SecureValueRecoveryForBackups_RemoveBackup(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<(), SvrbError> {
    let auth = Auth { username, password };
    let current_svrb = connection_manager
        .env()
        .svr_b
        .current()
        .map(|e| SvrBConnectImpl {
            connection_manager,
            endpoint: e,
            auth: &auth,
        })
        .collect::<Vec<_>>();
    let previous_svrb = connection_manager
        .env()
        .svr_b
        .previous()
        .map(|e| SvrBConnectImpl {
            connection_manager,
            endpoint: e,
            auth: &auth,
        })
        .collect::<Vec<_>>();

    remove_backup(&current_svrb, &previous_svrb).await
}

#[bridge_fn]
fn BackupStoreResponse_GetForwardSecrecyToken(
    response: &BackupStoreResponse,
) -> Result<[u8; BACKUP_FORWARD_SECRECY_TOKEN_LEN], SvrbError> {
    Ok(response.forward_secrecy_token.0)
}

#[bridge_fn]
fn BackupStoreResponse_GetOpaqueMetadata(
    response: &BackupStoreResponse,
) -> Result<&[u8], SvrbError> {
    Ok(&response.metadata.0)
}

#[bridge_fn]
fn BackupStoreResponse_GetNextBackupSecretData(response: &BackupStoreResponse) -> &[u8] {
    &response.next_backup_data.0
}

#[bridge_fn]
fn BackupRestoreResponse_GetForwardSecrecyToken(
    response: &BackupRestoreResponse,
) -> Result<[u8; BACKUP_FORWARD_SECRECY_TOKEN_LEN], SvrbError> {
    Ok(response.forward_secrecy_token.0)
}

#[bridge_fn]
fn BackupRestoreResponse_GetNextBackupSecretData(response: &BackupRestoreResponse) -> &[u8] {
    &response.next_backup_data.0
}
