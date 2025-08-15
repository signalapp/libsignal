//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net::auth::Auth;
use libsignal_net::cdsi::{self, CdsiConnection, ClientResponseCollector, Token};
use libsignal_net::infra::errors::RetryLater;
use libsignal_net::infra::tcp_ssl::InvalidProxyConfig;

use crate::net::ConnectionManager;
use crate::*;

#[cfg(feature = "jni")]
/// CDSI-protocol-specific subset of [`libsignal_net::cdsi::LookupError`] cases.
///
/// Contains cases for errors that aren't covered by other error types.
#[derive(Debug, displaydoc::Display)]
pub enum CdsiError {
    /// Protocol error after establishing a connection
    Protocol,
    /// Retry later
    RateLimited(RetryLater),
    /// Request token was invalid
    InvalidToken,
    /// CDS protocol: {0}
    CdsiProtocol(cdsi::CdsiProtocolError),
    /// Server error: {reason}
    Server { reason: &'static str },
}

#[derive(Default)]
pub struct LookupRequest(std::sync::Mutex<cdsi::LookupRequest>);

impl LookupRequest {
    pub fn lock(&self) -> impl std::ops::DerefMut<Target = cdsi::LookupRequest> + '_ {
        self.0.lock().expect("not poisoned")
    }
}

bridge_as_handle!(LookupRequest);

pub struct CdsiLookup {
    pub token: Token,
    remaining: std::sync::Mutex<Option<ClientResponseCollector>>,
}

impl CdsiLookup {
    pub async fn new_routes(
        connection_manager: &ConnectionManager,
        auth: &Auth,
        request: cdsi::LookupRequest,
    ) -> Result<Self, cdsi::LookupError> {
        let env_cdsi = &connection_manager.env.cdsi;

        let (connection_resources, route_provider) = connection_manager
            .enclave_connection_resources(env_cdsi)
            .map_err(|InvalidProxyConfig| {
                cdsi::LookupError::ConnectTransport(
                    libsignal_net::infra::errors::TransportConnectError::InvalidConfiguration,
                )
            })?;

        let connected = CdsiConnection::connect_with(
            connection_resources.as_connection_resources(),
            route_provider,
            env_cdsi.ws_config,
            &env_cdsi.params,
            auth,
        )
        .await?;
        let (token, remaining_response) = connected.send_request(request).await?;

        Ok(CdsiLookup {
            token,
            remaining: std::sync::Mutex::new(Some(remaining_response)),
        })
    }

    pub fn take_remaining(&self) -> Option<ClientResponseCollector> {
        self.remaining.lock().expect("not poisoned").take()
    }
}

bridge_as_handle!(CdsiLookup);
