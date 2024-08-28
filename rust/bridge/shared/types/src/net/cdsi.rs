//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net::auth::Auth;
use libsignal_net::cdsi::{self, CdsiConnection, ClientResponseCollector, Token};
use libsignal_net::infra::tcp_ssl::TcpSslConnectorStream;

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
    /// Invalid response received from the server
    InvalidResponse,
    /// Retry later
    RateLimited { retry_after: std::time::Duration },
    /// Failed to parse the response from the server
    ParseError,
    /// Request token was invalid
    InvalidToken,
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
    remaining: std::sync::Mutex<Option<ClientResponseCollector<TcpSslConnectorStream>>>,
}

impl CdsiLookup {
    pub async fn new(
        connection_manager: &ConnectionManager,
        auth: Auth,
        request: cdsi::LookupRequest,
    ) -> Result<Self, cdsi::LookupError> {
        let transport_connector = connection_manager
            .transport_connector
            .lock()
            .expect("not poisoned")
            .clone();
        let connected =
            CdsiConnection::connect(&connection_manager.cdsi, transport_connector, auth).await?;
        let (token, remaining_response) = connected.send_request(request).await?;

        Ok(CdsiLookup {
            token,
            remaining: std::sync::Mutex::new(Some(remaining_response)),
        })
    }

    pub fn take_remaining(&self) -> Option<ClientResponseCollector<TcpSslConnectorStream>> {
        self.remaining.lock().expect("not poisoned").take()
    }
}

bridge_as_handle!(CdsiLookup);
