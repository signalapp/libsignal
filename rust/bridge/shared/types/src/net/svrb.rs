//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use libsignal_account_keys::BACKUP_KEY_LEN;
use libsignal_net::auth::Auth;
use libsignal_net::enclave::{EnclaveEndpoint, PpssSetup, SvrSgx};
use libsignal_net::env::SvrBEnv;
use libsignal_net::infra::tcp_ssl::InvalidProxyConfig;
use libsignal_net::svr::SvrConnection;
use libsignal_net::svrb as svrb_impl;
use libsignal_net::svrb::traits::SvrBConnect;
use libsignal_net::svrb::{BackupRestoreResponse, BackupStoreResponse};
// Re-export the error type for FFI implementations
pub use svrb_impl::Error;

use crate::net::ConnectionManager;
use crate::*;

bridge_as_handle!(BackupStoreResponse);
bridge_as_handle!(BackupRestoreResponse);

pub type BackupKeyBytes = [u8; BACKUP_KEY_LEN];

pub struct SvrBConnectImpl<'a> {
    pub connection_manager: &'a ConnectionManager,
    // TODO: replace this with a method of selecting the enclave endpoint.
    pub endpoint: &'a EnclaveEndpoint<'a, SvrSgx>,
    pub auth: &'a Auth,
}

#[async_trait]
impl SvrBConnect for SvrBConnectImpl<'_> {
    type Env = SvrBEnv<'static>;

    async fn connect(&self) -> <Self::Env as PpssSetup>::ConnectionResults {
        let Self {
            connection_manager,
            auth,
            endpoint,
        } = self;

        let (connection_resources, route_provider) = connection_manager
            .enclave_connection_resources(endpoint)
            .map_err(|InvalidProxyConfig| {
                libsignal_net::ws::WebSocketServiceConnectError::invalid_proxy_configuration()
            })?;

        SvrConnection::connect(
            connection_resources.as_connection_resources(),
            route_provider,
            endpoint.ws_config,
            &endpoint.params,
            auth,
        )
        .await
    }
}
