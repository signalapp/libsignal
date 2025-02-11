//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use http::HeaderName;
use libsignal_net::auth::Auth;
use libsignal_net::cdsi::{self, CdsiConnection, ClientResponseCollector, Token};
use libsignal_net::infra::route::{DirectOrProxyProvider, RouteProviderExt};
use libsignal_net::infra::tcp_ssl::InvalidProxyConfig;
use libsignal_net::infra::AsHttpHeader as _;

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
    /// Response token was missing
    NoTokenInResponse,
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
        let endpoints = connection_manager
            .endpoints
            .lock()
            .expect("not poisoned")
            .clone();
        let connected = CdsiConnection::connect(&endpoints.cdsi, transport_connector, auth).await?;
        let (token, remaining_response) = connected.send_request(request).await?;

        Ok(CdsiLookup {
            token,
            remaining: std::sync::Mutex::new(Some(remaining_response)),
        })
    }

    pub async fn new_routes(
        connection_manager: &ConnectionManager,
        auth: Auth,
        request: cdsi::LookupRequest,
    ) -> Result<Self, cdsi::LookupError> {
        let ConnectionManager {
            env,
            dns_resolver,
            connect,
            user_agent,
            transport_connector,
            endpoints,
            ..
        } = connection_manager;

        let proxy_config: Option<libsignal_net::infra::route::ConnectionProxyConfig> =
            (&*transport_connector.lock().expect("not poisoned"))
                .try_into()
                .map_err(|InvalidProxyConfig| {
                    cdsi::LookupError::ConnectTransport(
                        libsignal_net::infra::errors::TransportConnectError::InvalidConfiguration,
                    )
                })?;

        let (ws_config, enable_domain_fronting) = {
            let guard = endpoints.lock().expect("not poisoned");
            (guard.cdsi.ws2_config(), guard.enable_fronting)
        };
        let env_cdsi = &env.cdsi;
        let route_provider =
            env_cdsi
                .route_provider(enable_domain_fronting)
                .map_routes(|mut route| {
                    route.fragment.headers.extend([user_agent.as_header()]);
                    route
                });
        let confirmation_header_name = env_cdsi
            .domain_config
            .connect
            .confirmation_header_name
            .map(HeaderName::from_static);

        let connected = CdsiConnection::connect_with(
            connect,
            dns_resolver,
            DirectOrProxyProvider::maybe_proxied(route_provider, proxy_config),
            confirmation_header_name,
            ws_config,
            &env.cdsi.params,
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
