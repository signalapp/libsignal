//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use libsignal_account_keys::{BackupKey, BACKUP_FORWARD_SECRECY_TOKEN_LEN, BACKUP_KEY_LEN};
use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_bridge_types::net::svrb::PreparedSvrBContext;
use libsignal_bridge_types::net::TokioAsyncContext;
use libsignal_net::enclave::{
    Error as EnclaveError, IntoConnectionResults, LabeledConnection, PpssSetup,
};
use libsignal_net::svrb::traits::SvrBConnect;
use libsignal_net::svrb::{
    finalize_backup, prepare_backup, restore_backup, BackupFileMetadataRef,
    BackupPreviousSecretDataRef, Error as SvrbError,
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

bridge_handle_fns!(PreparedSvrBContext, clone = false);

#[bridge_fn]
fn SecureValueRecoveryForBackups_PrepareBackupLocally(
    backup_key: &[u8; BACKUP_KEY_LEN],
    previous_metadata: &[u8],
    environment: AsType<Environment, u8>,
) -> Result<PreparedSvrBContext, SvrbError> {
    let backup_key: BackupKey = BackupKey(*backup_key);
    let _env = environment.into_inner().env();

    // Parse previous metadata if provided
    let previous_data = if previous_metadata.is_empty() {
        None
    } else {
        Some(BackupPreviousSecretDataRef(previous_metadata))
    };

    // TODO: Remove stub usage when we have a real SvrBConnect implementation
    let stub = StubSvrBConnect;
    prepare_backup(&stub, &backup_key, previous_data).map(Into::into)
}

#[bridge_io(TokioAsyncContext)]
async fn SecureValueRecoveryForBackups_FinalizeBackupWithServer(
    context: &PreparedSvrBContext,
    environment: AsType<Environment, u8>,
) -> Result<(), SvrbError> {
    let _env = environment.into_inner().env();

    // TODO: Remove stub usage when we have a real SvrBConnect implementation
    let stub = StubSvrBConnect;
    finalize_backup(&stub, &context.0.handle).await
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
fn PreparedSvrBContext_GetForwardSecrecyToken(
    response: &PreparedSvrBContext,
) -> Result<[u8; BACKUP_FORWARD_SECRECY_TOKEN_LEN], SvrbError> {
    Ok(response.0.forward_secrecy_token.0)
}

#[bridge_fn]
fn PreparedSvrBContext_GetOpaqueMetadata(
    response: &PreparedSvrBContext,
) -> Result<&[u8], SvrbError> {
    Ok(&response.0.metadata.0)
}
