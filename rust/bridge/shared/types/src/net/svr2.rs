//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net::auth::Auth;
use libsignal_net::enclave::{EnclaveEndpoint, IntoAttestedConnection as _, SvrSgx};
use libsignal_net::infra::errors::TransportConnectError;
use libsignal_net::infra::ws::WebSocketConnectError;
use libsignal_net::infra::ws::attested::AttestedConnection;
use libsignal_net::svr::SvrConnection;
use libsignal_net::svr2::Error;
pub use libsignal_net::svr2::{BackupSession as Svr2BackupSession, RestoreResult};

use crate::net::ConnectionManager;
use crate::*;

bridge_as_handle!(Svr2BackupSession);

/// High-level SVR2 API.
///
/// Opens a fresh attested connection to the given SVR2 enclave endpoint and
/// delegates the SVR2 operations to the low-level API in [`libsignal_net::svr2::ops`].
pub struct Svr2ConnectImpl<'a> {
    pub connection_manager: &'a ConnectionManager,
    pub endpoint: &'a EnclaveEndpoint<'a, SvrSgx>,
    pub auth: &'a Auth,
}

impl Svr2ConnectImpl<'_> {
    pub async fn connect(&self) -> Result<AttestedConnection, Error> {
        let (connection_resources, route_provider) = self
            .connection_manager
            .enclave_connection_resources(self.endpoint)
            .map_err(|_| {
                Error::Connect(WebSocketConnectError::Transport(
                    TransportConnectError::InvalidConfiguration,
                ))
            })?;

        let svr_conn = SvrConnection::connect(
            connection_resources.as_connection_resources(),
            self.endpoint.domain_config.connect.service,
            route_provider,
            self.endpoint.ws_config,
            &self.endpoint.params,
            self.auth,
        )
        .await
        .map_err(Error::from_enclave_error)?;

        Ok(svr_conn.into_labeled_connection().0)
    }
}
