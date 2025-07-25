//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use libsignal_account_keys::{BackupKey, BACKUP_FORWARD_SECRECY_TOKEN_LEN, BACKUP_KEY_LEN};
use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_bridge_types::net::svrb::StoreArgs;
use libsignal_bridge_types::net::TokioAsyncContext;
use libsignal_net::enclave::{
    Error as EnclaveError, IntoConnectionResults, LabeledConnection, PpssSetup,
};
use libsignal_net::svrb::traits::SvrBConnect;
use libsignal_net::svrb::{
    restore_backup, store_backup, BackupFileMetadataRef, BackupPreviousSecretDataRef,
    BackupResponse, Error as SvrbError,
};

use crate::net::Environment;
use crate::support::*;
use crate::*;

// Stub implementations of SvrBConnect until real implementation is available.
struct StubConnectionResults;

impl IntoConnectionResults for StubConnectionResults {
    type ConnectionResults = [Result<LabeledConnection, EnclaveError>; 1];

    fn into_connection_results(self) -> Self::ConnectionResults {
        [Err(EnclaveError::ConnectionTimedOut)]
    }
}

struct StubPpssSetup;

impl PpssSetup for StubPpssSetup {
    type ConnectionResults = StubConnectionResults;
    type ServerIds = [u64; 1];

    fn server_ids() -> Self::ServerIds {
        [1]
    }
}

struct StubSvrBConnect;

#[async_trait]
impl SvrBConnect for StubSvrBConnect {
    type Env = StubPpssSetup;

    async fn connect(&self) -> <Self::Env as PpssSetup>::ConnectionResults {
        StubConnectionResults
    }
}

bridge_handle_fns!(BackupResponse, clone = false);
bridge_handle_fns!(StoreArgs, clone = false);

// Bridging references into async functions doesn't work well. This function
// exists to take references and copy data into a 'static value that can be
// easily passed as a bridged handle to _StoreBackup below.
#[bridge_fn]
fn SecureValueRecoveryForBackups_CreateStoreArgs(
    backup_key: &[u8; BACKUP_KEY_LEN],
    previous_metadata: Box<[u8]>,
    environment: AsType<Environment, u8>,
) -> StoreArgs {
    StoreArgs {
        backup_key: BackupKey(*backup_key),
        previous_metadata,
        environment: environment.into_inner(),
    }
}

#[bridge_io(TokioAsyncContext)]
async fn SecureValueRecoveryForBackups_StoreBackup(
    store: &StoreArgs,
) -> Result<BackupResponse, SvrbError> {
    let StoreArgs {
        backup_key,
        previous_metadata,
        environment: _,
    } = store;

    // Parse previous metadata if provided
    let previous_data = if previous_metadata.is_empty() {
        None
    } else {
        Some(BackupPreviousSecretDataRef(previous_metadata))
    };

    // TODO: Remove stub usage when we have a real SvrBConnect implementation
    let stub = StubSvrBConnect;
    store_backup(&stub, backup_key, previous_data).await
}

#[bridge_io(TokioAsyncContext)]
async fn SecureValueRecoveryForBackups_RestoreBackupFromServer(
    backup_key: Box<[u8]>,
    metadata: Box<[u8]>,
    environment: AsType<Environment, u8>,
) -> Result<[u8; BACKUP_FORWARD_SECRECY_TOKEN_LEN], SvrbError> {
    let backup_key: BackupKey = BackupKey(
        backup_key
            .as_ref()
            .try_into()
            .map_err(|_| SvrbError::Protocol("Invalid backup key length".to_string()))?,
    );
    let _env = environment.into_inner().env();

    // Use stub implementation until real SvrBConnect is available
    let stub = StubSvrBConnect;
    restore_backup(&stub, &backup_key, BackupFileMetadataRef(&metadata))
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
