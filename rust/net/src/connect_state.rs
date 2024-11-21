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
use libsignal_net_infra::ws::WebSocketConnectError;
use libsignal_net_infra::ws2::attested::AttestedConnection;
use libsignal_net_infra::{AsHttpHeader as _, AsyncDuplexStream};
use tokio::time::Instant;

use crate::auth::Auth;
use crate::ws::WebSocketServiceConnectError;

/// Endpoint-agnostic state for establishing a connection with
/// [`crate::infra::route::connect`].
pub struct ConnectState<TC = StatelessTransportConnector> {
    pub route_resolver: RouteResolver,
    /// Transport-level connector used for all connections.
    transport_connector: TC,
    /// Record of connection outcomes.
    attempts_record: ConnectionOutcomes<WebSocketServiceRoute>,
}

impl ConnectState {
    pub fn new(connect_params: ConnectionOutcomeParams) -> tokio::sync::RwLock<Self> {
        Self {
            route_resolver: RouteResolver::default(),
            transport_connector: StatelessTransportConnector::default(),
            attempts_record: ConnectionOutcomes::new(connect_params),
        }
        .into()
    }
}

impl<TC> ConnectState<TC>
where
    TC: Connector<TransportRoute, ()> + Sync,
    TC::Error: Into<WebSocketConnectError>,
{
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
                TC::Connection,
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

        // Drop our read lock so we can re-acquire as a writer. It's okay if we
        // race with other writers since the order in which updates are applied
        // doesn't matter.
        drop(connect_read);

        this.write()
            .await
            .attempts_record
            .apply_outcome_updates(updates.outcomes, updates.finished_at);

        result
    }

    pub(crate) async fn connect_attested_ws(
        connect: &tokio::sync::RwLock<Self>,
        routes: impl RouteProvider<Route = UnresolvedWebsocketServiceRoute>,
        auth: Auth,
        resolver: &DnsResolver,
        confirmation_header_name: Option<HeaderName>,
        ws_config: libsignal_net_infra::ws2::Config,
        new_handshake: impl FnOnce(&[u8]) -> Result<attest::enclave::Handshake, attest::enclave::Error>,
    ) -> Result<AttestedConnection, crate::enclave::Error>
    where
        TC::Connection: AsyncDuplexStream + 'static,
    {
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

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use assert_matches::assert_matches;
    use const_str::ip_addr;
    use http::uri::PathAndQuery;
    use http::HeaderMap;
    use libsignal_net_infra::certs::RootCertificates;
    use libsignal_net_infra::dns::lookup_result::LookupResult;
    use libsignal_net_infra::host::Host;
    use libsignal_net_infra::route::testutils::ConnectFn;
    use libsignal_net_infra::route::{
        DirectOrProxyRoute, HttpsTlsRoute, TcpRoute, TlsRoute, TlsRouteFragment, UnresolvedHost,
        WebSocketRoute,
    };
    use libsignal_net_infra::{Alpn, DnsSource};
    use nonzero_ext::nonzero;

    use super::*;

    const FAKE_CONNECT_PARAMS: ConnectionOutcomeParams = ConnectionOutcomeParams {
        age_cutoff: Duration::from_secs(100),
        cooldown_growth_factor: 10.0,
        count_growth_factor: 10.0,
        max_count: 3,
        max_delay: Duration::from_secs(5),
    };

    #[tokio::test(start_paused = true)]
    async fn connect_ws_successful() {
        // This doesn't actually matter since we're using a fake connector, but
        // using the real route type is easier than trying to add yet more
        // generic parameters.
        let fake_transport_route = TlsRoute {
            fragment: TlsRouteFragment {
                root_certs: RootCertificates::Native,
                sni: Host::Domain("fake-sni".into()),
                alpn: Some(Alpn::Http1_1),
            },
            inner: DirectOrProxyRoute::Direct(TcpRoute {
                address: UnresolvedHost::from(Arc::from("direct-host")),
                port: nonzero!(1234u16),
            }),
        };

        let failing_route = WebSocketRoute {
            fragment: WebSocketRouteFragment {
                ws_config: Default::default(),
                endpoint: PathAndQuery::from_static("/failing"),
                headers: HeaderMap::new(),
            },
            inner: HttpsTlsRoute {
                fragment: HttpRouteFragment {
                    host_header: "failing-host".into(),
                    path_prefix: "".into(),
                },
                inner: fake_transport_route.clone(),
            },
        };

        let succeeding_route = WebSocketRoute {
            fragment: WebSocketRouteFragment {
                ws_config: Default::default(),
                endpoint: PathAndQuery::from_static("/successful"),
                headers: HeaderMap::new(),
            },
            inner: HttpsTlsRoute {
                fragment: HttpRouteFragment {
                    host_header: "successful-host".into(),
                    path_prefix: "".into(),
                },
                inner: fake_transport_route,
            },
        };

        let ws_connector = ConnectFn(|(), route| {
            let (ws, http) = &route;
            std::future::ready(
                if (ws, http) == (&failing_route.fragment, &failing_route.inner.fragment) {
                    Err(tungstenite::Error::ConnectionClosed)
                } else {
                    Ok(route)
                },
            )
        });
        let resolver = DnsResolver::new_from_static_map(HashMap::from([(
            "direct-host",
            LookupResult::new(DnsSource::Static, vec![ip_addr!(v4, "1.1.1.1")], vec![]),
        )]));

        let fake_transport_connector =
            ConnectFn(move |(), _| std::future::ready(Ok::<_, WebSocketConnectError>(())));

        let state = ConnectState {
            route_resolver: RouteResolver::default(),
            attempts_record: ConnectionOutcomes::new(FAKE_CONNECT_PARAMS),
            transport_connector: fake_transport_connector,
        }
        .into();

        let result = ConnectState::connect_ws(
            &state,
            vec![failing_route.clone(), succeeding_route.clone()],
            ws_connector,
            &resolver,
            None,
            |e| {
                let e = assert_matches!(e, WebSocketServiceConnectError::Connect(e, _) => e);
                assert_matches!(
                    e,
                    WebSocketConnectError::WebSocketError(tungstenite::Error::ConnectionClosed)
                );
                ControlFlow::<()>::Continue(())
            },
        )
        // This previously hung forever due to a deadlock bug.
        .await;

        assert_eq!(
            result,
            Ok((succeeding_route.fragment, succeeding_route.inner.fragment))
        )
    }
}
