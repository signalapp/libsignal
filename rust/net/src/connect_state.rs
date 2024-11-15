//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::default::Default;
use std::ops::ControlFlow;

use http::HeaderName;
use libsignal_net_infra::connection_manager::{ErrorClass, ErrorClassifier as _};
use libsignal_net_infra::dns::DnsResolver;
use libsignal_net_infra::route::{
    ComposedConnector, ConnectError, ConnectionOutcomeParams, ConnectionOutcomes, Connector,
    HttpRouteFragment, RouteProvider, RouteProviderExt as _, RouteResolver,
    StatelessTransportConnector, TransportRoute, UnresolvedWebsocketServiceRoute,
    WebSocketRouteFragment, WebSocketServiceRoute,
};
use libsignal_net_infra::ws2::attested::AttestedConnection;
use libsignal_net_infra::AsHttpHeader as _;
use tokio::time::Instant;

use crate::auth::Auth;
use crate::ws::WebSocketServiceConnectError;

/// Endpoint-agnostic state for establishing a connection with
/// [`crate::infra::route::connect`].
pub struct ConnectState {
    pub route_resolver: RouteResolver,
    /// Transport-level connector used for all connections.
    transport_connector: StatelessTransportConnector,
    /// Record of connection outcomes.
    attempts_record: ConnectionOutcomes<WebSocketServiceRoute>,
}

/// The type of connection produced by [`StatelessTransportConnector`].
///
/// Extracted as a type alias for readability.
type StatelessTransportConnection =
    <StatelessTransportConnector as Connector<TransportRoute, ()>>::Connection;

impl ConnectState {
    pub fn new(connect_params: ConnectionOutcomeParams) -> tokio::sync::RwLock<Self> {
        Self {
            route_resolver: RouteResolver::default(),
            transport_connector: StatelessTransportConnector::default(),
            attempts_record: ConnectionOutcomes::new(connect_params),
        }
        .into()
    }

    pub async fn connect_ws<WC, E>(
        this: &tokio::sync::RwLock<Self>,
        routes: impl RouteProvider<Route = UnresolvedWebsocketServiceRoute>,
        ws_connector: WC,
        resolver: &DnsResolver,
        confirmation_header_name: Option<&HeaderName>,
        mut on_error: impl FnMut(WebSocketServiceConnectError) -> ControlFlow<E>,
    ) -> Result<WC::Connection, ConnectError<E>>
    where
        WC: Connector<
                (WebSocketRouteFragment, HttpRouteFragment),
                StatelessTransportConnection,
                Error = tungstenite::Error,
            > + Send
            + Sync,
    {
        let connect_read = this.read().await;

        let (result, updates) = crate::infra::route::connect(
            &connect_read.route_resolver,
            &connect_read.attempts_record,
            routes,
            resolver,
            ComposedConnector::new(ws_connector, &connect_read.transport_connector),
            |error| {
                let error = WebSocketServiceConnectError::from_websocket_error(
                    error,
                    confirmation_header_name,
                    Instant::now(),
                );
                on_error(error)
            },
        )
        .await;

        this.write()
            .await
            .attempts_record
            .apply_outcome_updates(updates.outcomes, updates.finished_at);

        result
    }

    pub(crate) async fn connect_attested_ws(
        connect: &tokio::sync::RwLock<ConnectState>,
        routes: impl RouteProvider<Route = UnresolvedWebsocketServiceRoute>,
        auth: Auth,
        resolver: &DnsResolver,
        confirmation_header_name: Option<HeaderName>,
        ws_config: libsignal_net_infra::ws2::Config,
        new_handshake: impl FnOnce(&[u8]) -> Result<attest::enclave::Handshake, attest::enclave::Error>,
    ) -> Result<AttestedConnection, crate::enclave::Error> {
        let ws_routes = routes.map_routes(|mut route| {
            route.fragment.headers.extend([auth.as_header()]);
            route
        });

        let ws = ConnectState::connect_ws(
            connect,
            ws_routes,
            crate::infra::ws::Stateless,
            resolver,
            confirmation_header_name.as_ref(),
            |error| match error.classify() {
                ErrorClass::Intermittent => ControlFlow::Continue(()),
                ErrorClass::RetryAt(_) | ErrorClass::Fatal => {
                    ControlFlow::Break(crate::enclave::Error::WebSocketConnect(error))
                }
            },
        )
        .await
        .map_err(|e| match e {
            ConnectError::NoResolvedRoutes | ConnectError::AllAttemptsFailed => {
                crate::enclave::Error::ConnectionTimedOut
            }
            ConnectError::FatalConnect(e) => e,
        })?;

        AttestedConnection::connect(ws, ws_config, new_handshake)
            .await
            .map_err(Into::into)
    }
}
