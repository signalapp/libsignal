//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use libsignal_account_keys::BackupKey;
use libsignal_net::auth::Auth;
use libsignal_net::enclave::PpssSetup;
use libsignal_net::env::SvrBEnv;
use libsignal_net::infra::tcp_ssl::InvalidProxyConfig;
use libsignal_net::svr::SvrConnection;
use libsignal_net::svrb as svrb_impl;
use libsignal_net::svrb::traits::SvrBConnect;
use libsignal_net::svrb::BackupResponse;
// Re-export the error type for FFI implementations
pub use svrb_impl::Error;

use crate::net::{ConnectionManager, Environment};
use crate::*;

bridge_as_handle!(BackupResponse);

pub struct StoreArgs {
    pub backup_key: BackupKey,
    pub previous_secret_data: Box<[u8]>,
    pub environment: Environment,
}

bridge_as_handle!(StoreArgs);

pub struct SvrBConnectImpl<'a> {
    pub connection_manager: &'a ConnectionManager,
    pub auth: Auth,
}

#[async_trait]
impl SvrBConnect for SvrBConnectImpl<'_> {
    type Env = SvrBEnv<'static>;

    async fn connect(&self) -> <Self::Env as PpssSetup>::ConnectionResults {
        let Self {
            connection_manager,
            auth,
        } = self;
        let env_svrb = connection_manager.env.svr_b.sgx();

        let (connection_resources, route_provider) = connection_manager
            .enclave_connection_resources(env_svrb)
            .map_err(|InvalidProxyConfig| {
                libsignal_net::ws::WebSocketServiceConnectError::invalid_proxy_configuration()
            })?;

        SvrConnection::connect(
            connection_resources.as_connection_resources(),
            route_provider,
            env_svrb.ws_config,
            &env_svrb.params,
            auth.clone(),
        )
        .await
    }
}
