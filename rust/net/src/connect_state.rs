//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::default::Default;
use std::fmt::Debug;
use std::future::Future;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use assert_matches::debug_assert_matches;
use futures_util::TryFutureExt as _;
use http::HeaderName;
use itertools::Itertools as _;
use libsignal_net_infra::AsHttpHeader as _;
use libsignal_net_infra::dns::DnsResolver;
use libsignal_net_infra::errors::{LogSafeDisplay, TransportConnectError};
use libsignal_net_infra::http_client::HttpConnectError;
use libsignal_net_infra::route::{
    AttemptOutcome, ComposedConnector, ConnectError, ConnectionOutcomeParams, ConnectionOutcomes,
    ConnectionProxyConfig, Connector, ConnectorFactory, DelayBasedOnTransport, DescribeForLog,
    DescribedRouteConnector, DirectOrProxy, DirectOrProxyMode, DirectOrProxyRoute,
    HttpRouteFragment, HttpsServiceRoute, InterfaceChangedOr, InterfaceMonitor, LoggingConnector,
    ResettingConnectionOutcomes, ResolveHostnames, ResolveWithSavedDescription, ResolvedRoute,
    RouteProvider, RouteProviderContext, RouteProviderExt as _, RouteResolver,
    StaticTcpTimeoutConnector, ThrottlingConnector, TransportRoute, UnresolvedRouteDescription,
    UnresolvedTransportRoute, UnresolvedWebsocketServiceRoute, UnsuccessfulOutcome, UsePreconnect,
    UsesTransport, VariableTlsTimeoutConnector, WebSocketRouteFragment, WebSocketServiceRoute,
};
use libsignal_net_infra::tcp_ssl::{LONG_TCP_HANDSHAKE_THRESHOLD, LONG_TLS_HANDSHAKE_THRESHOLD};
use libsignal_net_infra::timeouts::{
    MIN_TLS_HANDSHAKE_TIMEOUT, NETWORK_INTERFACE_POLL_INTERVAL, ONE_ROUTE_CONNECTION_TIMEOUT,
    POST_ROUTE_CHANGE_CONNECTION_TIMEOUT, TimeoutOr,
};
use libsignal_net_infra::utils::NetworkChangeEvent;
use libsignal_net_infra::ws::attested::AttestedConnection;
use libsignal_net_infra::ws::{WebSocketConnectError, WebSocketTransportStream};
use rand::distr::uniform::{UniformSampler, UniformUsize};
use rand_core::{OsRng, UnwrapErr};
use static_assertions::assert_eq_size_val;
use tokio::time::Instant;

use crate::auth::Auth;
use crate::enclave::{EndpointParams, NewHandshake};
use crate::ws::WebSocketServiceConnectError;

/// Suggested values for [`ConnectionOutcomeParams`].
pub const SUGGESTED_CONNECT_PARAMS: ConnectionOutcomeParams = ConnectionOutcomeParams {
    short_term_age_cutoff: Duration::from_secs(5 * 60),
    long_term_age_cutoff: Duration::from_secs(6 * 60 * 60),
    cooldown_growth_factor: 10.0,
    max_count: 5,
    max_delay: Duration::from_secs(30),
    count_growth_factor: 10.0,
};

/// Suggested values for [`Config`].
pub const SUGGESTED_CONNECT_CONFIG: Config = Config {
    connect_params: SUGGESTED_CONNECT_PARAMS,
    connect_timeout: ONE_ROUTE_CONNECTION_TIMEOUT,
    network_interface_poll_interval: NETWORK_INTERFACE_POLL_INTERVAL,
    post_route_change_connect_timeout: POST_ROUTE_CHANGE_CONNECTION_TIMEOUT,
};

/// Suggested lifetime for a [`PreconnectingFactory`]'s connector that handles up to a TLS
/// handshake.
pub const SUGGESTED_TLS_PRECONNECT_LIFETIME: Duration = Duration::from_millis(1500);

/// Effectively an alias for [`ConnectorFactory`] with connection, route, and error
/// requirements appropriate for websockets.
///
/// Meant to be simpler to write at use sites.
pub trait WebSocketTransportConnectorFactory<Transport = TransportRoute>:
    // rustfmt makes some weird choices without this comment blocking it.
    ConnectorFactory<
        Transport,
        Connector: Sync + Connector<Transport, (), Error: Into<WebSocketConnectError>>,
        Connection: WebSocketTransportStream,
    >
{
}

impl<F, Transport> WebSocketTransportConnectorFactory<Transport> for F where
    F: ConnectorFactory<
            Transport,
            Connector: Sync + Connector<Transport, (), Error: Into<WebSocketConnectError>>,
            Connection: WebSocketTransportStream,
        >
{
}

/// Endpoint-agnostic state for establishing a connection with
/// [`crate::infra::route::connect`].
///
/// Templated over the type of the transport connector to support testing.
pub struct ConnectState<ConnectorFactory = DefaultConnectorFactory> {
    pub route_resolver: RouteResolver,
    /// The amount of time allowed for each connection attempt.
    pub connect_timeout: Duration,
    /// How often to check if the network interface has changed, given no other info.
    network_interface_poll_interval: Duration,
    /// The amount of time allowed for a connection attempt after a network change.
    post_route_change_connect_timeout: Duration,
    /// Transport-level connector used for all connections.
    make_transport_connector: ConnectorFactory,
    /// Record of connection outcomes.
    attempts_record: ConnectionOutcomes<TransportRoute>,
    /// [`RouteProviderContext`] passed to route providers.
    route_provider_context: RouteProviderContextImpl,
}

pub type DefaultTransportConnector = VariableTlsTimeoutConnector<
    ThrottlingConnector<LoggingConnector<crate::infra::tcp_ssl::StatelessTls>>,
    crate::infra::route::DirectOrProxy<
        LoggingConnector<StaticTcpTimeoutConnector<crate::infra::tcp_ssl::StatelessTcp>>,
        crate::infra::tcp_ssl::proxy::StatelessProxied,
        TransportConnectError,
    >,
    TransportConnectError,
>;

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub connect_params: ConnectionOutcomeParams,
    pub connect_timeout: Duration,
    pub network_interface_poll_interval: Duration,
    pub post_route_change_connect_timeout: Duration,
}

pub struct ConnectionResources<'a, TC> {
    pub connect_state: &'a std::sync::Mutex<ConnectState<TC>>,
    pub dns_resolver: &'a DnsResolver,
    pub network_change_event: &'a NetworkChangeEvent,
    pub confirmation_header_name: Option<HeaderName>,
}

pub struct DefaultConnectorFactory;
impl<R> ConnectorFactory<R> for DefaultConnectorFactory
where
    DefaultTransportConnector: Connector<R, ()>,
{
    type Connector = DefaultTransportConnector;
    type Connection = <DefaultTransportConnector as Connector<R, ()>>::Connection;

    fn make(&self) -> Self::Connector {
        let throttle_tls_connections = ThrottlingConnector::new(
            LoggingConnector::new(Default::default(), LONG_TLS_HANDSHAKE_THRESHOLD, "TLS"),
            1,
        );
        let proxy_or_direct_connector = DirectOrProxy::new(
            LoggingConnector::new(
                StaticTcpTimeoutConnector::default(),
                LONG_TCP_HANDSHAKE_THRESHOLD,
                "TCP",
            ),
            // Proxy connectors use LoggingConnector internally
            Default::default(),
        );
        VariableTlsTimeoutConnector::new(
            throttle_tls_connections,
            proxy_or_direct_connector,
            MIN_TLS_HANDSHAKE_TIMEOUT,
        )
    }
}

impl ConnectState {
    pub fn new(config: Config) -> std::sync::Mutex<Self> {
        Self::new_with_transport_connector(config, DefaultConnectorFactory)
    }
}

impl<ConnectorFactory> ConnectState<ConnectorFactory> {
    pub fn new_with_transport_connector(
        config: Config,
        make_transport_connector: ConnectorFactory,
    ) -> std::sync::Mutex<Self> {
        let Config {
            connect_params,
            connect_timeout,
            network_interface_poll_interval,
            post_route_change_connect_timeout,
        } = config;
        Self {
            route_resolver: RouteResolver::default(),
            connect_timeout,
            network_interface_poll_interval,
            post_route_change_connect_timeout,
            make_transport_connector,
            attempts_record: ConnectionOutcomes::new(connect_params),
            route_provider_context: RouteProviderContextImpl::default(),
        }
        .into()
    }

    pub fn network_changed(&mut self, network_change_time: Instant) {
        self.attempts_record.reset(network_change_time);
    }
}

#[non_exhaustive]
#[derive(Clone, Debug, PartialEq)]
pub struct RouteInfo {
    pub unresolved: UnresolvedRouteDescription,
}

impl LogSafeDisplay for RouteInfo {}
impl std::fmt::Display for RouteInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { unresolved } = self;
        (unresolved as &dyn LogSafeDisplay).fmt(f)
    }
}

impl RouteInfo {
    pub fn fake() -> Self {
        Self {
            unresolved: UnresolvedRouteDescription::fake(),
        }
    }
}

/// A snapshot of [`ConnectState`] for a particular connection attempt.
///
/// "Like `ConnectState`, but with a single instantiated connector."
struct ConnectStateSnapshot<C> {
    route_resolver: RouteResolver,
    connect_timeout: Duration,
    network_interface_poll_interval: Duration,
    post_route_change_connect_timeout: Duration,
    transport_connector: C,
    attempts_record: ConnectionOutcomes<TransportRoute>,
    route_provider_context: RouteProviderContextImpl,
}

impl<TC> ConnectState<TC> {
    fn prepare_snapshot<Transport>(&mut self) -> ConnectStateSnapshot<TC::Connector>
    where
        TC: ConnectorFactory<Transport>,
    {
        let Self {
            route_resolver,
            connect_timeout,
            network_interface_poll_interval,
            post_route_change_connect_timeout,
            make_transport_connector,
            attempts_record,
            route_provider_context,
        } = self;

        attempts_record.reset_if_system_has_probably_been_asleep(SystemTime::now());

        ConnectStateSnapshot {
            route_resolver: route_resolver.clone(),
            connect_timeout: *connect_timeout,
            network_interface_poll_interval: *network_interface_poll_interval,
            post_route_change_connect_timeout: *post_route_change_connect_timeout,
            transport_connector: make_transport_connector.make(),
            attempts_record: attempts_record.clone(),
            route_provider_context: route_provider_context.clone(),
        }
    }
}

impl<TC> ConnectionResources<'_, TC> {
    pub async fn connect_ws<WC, UR, Transport>(
        mut self,
        routes: impl RouteProvider<Route = UR>,
        ws_connector: WC,
        log_tag: &str,
    ) -> Result<(WC::Connection, RouteInfo), TimeoutOr<ConnectError<WebSocketServiceConnectError>>>
    where
        // Our routes should be unresolved and describable, but resolve to a WebSocketServiceRoute
        // with a custom Transport (to support preconnecting the transport).
        UR: ResolveHostnames<Resolved = WebSocketServiceRoute<Transport>>
            + DescribeForLog<Description = UnresolvedRouteDescription>
            + Clone
            + 'static,
        // The transport needs to provide properties that are required of the resolved route.
        Transport: Clone + Send + UsesTransport + ResolvedRoute,
        // The transport connector factory needs to (a) connect over Transport, and (b) have a
        // compatible error type.
        // Note that we're not using WebSocketTransportConnectorFactory here to make `connect_ws`
        // easier to test; specifically, the output is not guaranteed to be a WebSocketTransportStream.
        TC: ConnectorFactory<
                Transport,
                Connection: Send,
                Connector: Sync + Connector<Transport, (), Error: Into<WebSocketConnectError>>,
            >,
        // The websocket-level connector matches the shape of `ws::Stateless`, but might be
        // something else for testing purposes.
        WC: Connector<
                (WebSocketRouteFragment, HttpRouteFragment),
                TC::Connection,
                Connection: Send,
                Error = WebSocketConnectError,
            > + Sync,
    {
        let confirmation_header_name = self.confirmation_header_name.take();
        self.connect_over_transport(
            routes,
            LoggingConnector::new(ws_connector, Duration::from_secs(3), "ws"),
            log_tag,
            |error| {
                let error = error.into_inner_or_else(|| {
                    WebSocketConnectError::Transport(TransportConnectError::ClientAbort)
                });
                let error = WebSocketServiceConnectError::from_websocket_error(
                    error,
                    confirmation_header_name.as_ref(),
                    Instant::now(),
                );
                log::debug!("[{log_tag}] connection attempt failed with {error}");
                let is_fatal = match &error {
                    WebSocketServiceConnectError::RejectedByServer {
                        response,
                        received_at: _,
                    } => {
                        log::trace!("[{log_tag}] full response: {response:?}");
                        // Retry-After takes precedence over everything else.
                        libsignal_net_infra::extract_retry_later(response.headers()).is_some() ||
                        // If we're rejected based on the request (4xx), there's no point in retrying.
                        response.status().is_client_error()
                    }
                    WebSocketServiceConnectError::Connect(
                        connect_error,
                        crate::ws::NotRejectedByServer { .. },
                    ) => {
                        // If we *locally* chose to abort, that isn't route-specific; treat it as fatal.
                        // In any other case, if we didn't make it to the server, we should retry.
                        matches!(
                            connect_error,
                            WebSocketConnectError::Transport(TransportConnectError::ClientAbort)
                        )
                    }
                };
                if is_fatal {
                    ControlFlow::Break(error)
                } else {
                    ControlFlow::Continue(())
                }
            },
        )
        .await
    }

    pub(crate) async fn connect_attested_ws<E>(
        self,
        routes: impl RouteProvider<Route = UnresolvedWebsocketServiceRoute>,
        auth: &Auth,
        ws_config: libsignal_net_infra::ws::Config,
        log_tag: Arc<str>,
        params: &EndpointParams<'_, E>,
    ) -> Result<(AttestedConnection, RouteInfo), crate::enclave::Error>
    where
        TC: WebSocketTransportConnectorFactory,
        E: NewHandshake,
    {
        let ws_routes = routes.map_routes(|mut route| {
            route.fragment.headers.extend([auth.as_header()]);
            route
        });

        // We don't want to race multiple websocket handshakes because when
        // we take the first one, the others will be uncermoniously closed.
        // That looks like unexpected behavior at the server end, and the
        // wasted handshakes consume resources unnecessarily.  Instead,
        // allow parallelism at the transport level but throttle the number
        // of websocket handshakes that can complete.
        let ws_connector =
            ThrottlingConnector::new(crate::infra::ws::WithoutResponseHeaders::new(), 1);

        let (ws, route_info) = self
            .connect_ws(ws_routes, ws_connector, &log_tag)
            .await
            .map_err(|e| match e {
                TimeoutOr::Other(
                    ConnectError::NoResolvedRoutes | ConnectError::AllAttemptsFailed,
                )
                | TimeoutOr::Timeout {
                    attempt_duration: _,
                } => crate::enclave::Error::AllConnectionAttemptsFailed,
                TimeoutOr::Other(ConnectError::FatalConnect(e)) => e.into(),
            })?;

        let connection =
            AttestedConnection::connect(ws, ws_config, log_tag, move |attestation_message| {
                E::new_handshake(params, attestation_message)
            })
            .await?;
        Ok((connection, route_info))
    }

    pub async fn connect_h2<HC, UR, Transport>(
        self,
        routes: impl RouteProvider<Route = UR>,
        h2_connector: HC,
        log_tag: &str,
    ) -> Result<(HC::Connection, RouteInfo), TimeoutOr<ConnectError<HttpConnectError>>>
    where
        // Our routes should be unresolved and describable, but resolve to an HttpsServiceRoute
        // with a custom Transport (to support preconnecting the transport).
        UR: ResolveHostnames<Resolved = HttpsServiceRoute<Transport>>
            + DescribeForLog<Description = UnresolvedRouteDescription>
            + Clone
            + 'static,
        // The transport needs to provide properties that are required of the resolved route.
        Transport: Clone + Send + UsesTransport + ResolvedRoute,
        // The transport connector factory needs to (a) connect over Transport, and (b) have a
        // compatible error type.
        TC: ConnectorFactory<
                Transport,
                Connection: Send,
                Connector: Sync + Connector<Transport, (), Error: Into<HttpConnectError>>,
            >,
        // The H2-level connector matches the shape of `Http2Connector`, but might be something else
        // for testing purposes.
        HC: Connector<HttpRouteFragment, TC::Connection, Connection: Send, Error = HttpConnectError>
            + Sync,
    {
        self.connect_over_transport(
            routes,
            LoggingConnector::new(h2_connector, Duration::from_secs(3), "h2"),
            log_tag,
            |error| {
                let error = error.into_inner_or_else(|| {
                    HttpConnectError::Transport(TransportConnectError::ClientAbort)
                });
                log::debug!("[{log_tag}] connection attempt failed with {error}");
                // Note: the H2 handshake doesn't provide a confirmation header, so we have to treat
                // any failures as route-specific (other than choosing to abort).
                let is_fatal = matches!(
                    error,
                    HttpConnectError::Transport(TransportConnectError::ClientAbort)
                );
                if is_fatal {
                    ControlFlow::Break(error)
                } else {
                    ControlFlow::Continue(())
                }
            },
        )
        .await
    }

    async fn connect_over_transport<HC, UR, Transport, Fragment, FatalError>(
        self,
        routes: impl RouteProvider<Route = UR>,
        high_level_connector: HC,
        log_tag: &str,
        on_error: impl FnMut(InterfaceChangedOr<HC::Error>) -> ControlFlow<FatalError>,
    ) -> Result<(HC::Connection, RouteInfo), TimeoutOr<ConnectError<FatalError>>>
    where
        // Our routes should be unresolved and describable, plus whatever we'll need for connecting.
        UR: ResolveHostnames<Resolved: Clone + Send + UsesTransport>
            + DescribeForLog<Description = UnresolvedRouteDescription>
            + Clone
            + 'static,
        // Our transport connector factory has very minimal requirements about thread safety.
        // (Note that Transport is unconstrained here! We get all we need from the ComposedConnector
        // constraint below.)
        TC: ConnectorFactory<Transport, Connector: Sync>,
        // Similarly, the high-level connector mostly just connects over the low-level connection
        // *somehow,* plus thread-safety.
        HC: Connector<Fragment, TC::Connection> + Sync,
        // What we really care about is that we can compose the two connectors to get a full
        // connection over the resolved route.
        for<'a> ComposedConnector<HC, &'a TC::Connector>:
            Connector<UR::Resolved, (), Connection = HC::Connection, Error = HC::Error>,
        // And if we have any fatal errors, we want to be able to log them.
        FatalError: LogSafeDisplay,
    {
        let Self {
            connect_state,
            dns_resolver,
            network_change_event,
            confirmation_header_name: _,
        } = self;

        let ConnectStateSnapshot {
            route_resolver,
            connect_timeout,
            network_interface_poll_interval,
            post_route_change_connect_timeout,
            transport_connector,
            attempts_record,
            route_provider_context,
        } = connect_state
            .lock()
            .expect("not poisoned")
            .prepare_snapshot();

        let routes = routes.routes(&route_provider_context).collect_vec();

        log::info!(
            "[{log_tag}] starting connection attempt with {} routes",
            routes.len()
        );

        let route_provider = routes.into_iter().map(ResolveWithSavedDescription);
        let connector = InterfaceMonitor::new(
            DescribedRouteConnector(ComposedConnector::new(
                high_level_connector,
                &transport_connector,
            )),
            network_change_event.clone(),
            network_interface_poll_interval,
            post_route_change_connect_timeout,
        );
        let delay_policy = DelayBasedOnTransport(ResettingConnectionOutcomes::new(
            attempts_record,
            network_change_event,
        ));

        let start = Instant::now();
        let connect = crate::infra::route::connect(
            &route_resolver,
            delay_policy,
            route_provider,
            dns_resolver,
            connector,
            (),
            log_tag,
            on_error,
        );

        let (result, updates) = tokio::time::timeout(connect_timeout, connect)
            .await
            .map_err(|_: tokio::time::error::Elapsed| TimeoutOr::Timeout {
                attempt_duration: connect_timeout,
            })?;

        match &result {
            Ok((_connection, route)) => log::info!(
                "[{log_tag}] connection through {route} succeeded after {:.3?}",
                updates.finished_at - start
            ),
            Err(e) => log::info!("[{log_tag}] connection failed with {e}"),
        }

        let outcomes = process_outcomes(updates.outcomes);

        connect_state
            .lock()
            .expect("not poisoned")
            .attempts_record
            .apply_outcome_updates(outcomes, updates.finished_at, SystemTime::now());

        let (connection, description) = result?;
        Ok((
            connection,
            RouteInfo {
                unresolved: description,
            },
        ))
    }
}

fn process_outcomes<R: UsesTransport>(
    mut outcomes: Vec<(R, AttemptOutcome)>,
) -> impl Iterator<Item = (TransportRoute, AttemptOutcome)> {
    // First pass: collect information, tentatively tag proxies as LongTerm outcomes.
    // This in-place tagging avoids checking whether a route is a proxy route a second time.
    let mut any_direct_successes = false;
    let mut any_proxy_successes = false;
    for (route, outcome) in &mut outcomes {
        match route.transport_part().inner {
            DirectOrProxyRoute::Direct(_) => {
                any_direct_successes |= outcome.result.is_ok();
            }
            DirectOrProxyRoute::Proxy(_) if outcome.result.is_err() => {
                debug_assert_matches!(
                    outcome.result.expect_err("just checked"),
                    UnsuccessfulOutcome::ShortTerm,
                    "no routes should be tagged as long term yet"
                );
                outcome.result = Err(UnsuccessfulOutcome::LongTerm);
            }
            DirectOrProxyRoute::Proxy(_) => {
                any_proxy_successes = true;
            }
        }
    }

    // Second (deferred) pass: drop unneeded route info, decide whether to use our tentative tags.
    outcomes.into_iter().map(move |(r, outcome)| {
        (
            r.into_transport_part(),
            AttemptOutcome {
                result: outcome.result.map_err(|failure| {
                    if any_direct_successes && !any_proxy_successes {
                        failure
                    } else {
                        // If no direct route succeeded, or if a proxy route *did* succeed, undo our
                        // tentative tag as LongTerm.
                        UnsuccessfulOutcome::ShortTerm
                    }
                }),
                ..outcome
            },
        )
    })
}

impl<TC> ConnectionResources<'_, PreconnectingFactory<TC>>
where
    // Note that we're not using WebSocketTransportConnectorFactory here to make `connect_ws`
    // easier to test; specifically, the output is not guaranteed to be a WebSocketTransportStream.
    TC: ConnectorFactory<TransportRoute, Connector: Sync, Connection: Send>,
{
    pub async fn preconnect_and_save(
        self,
        routes: impl RouteProvider<Route = UnresolvedTransportRoute>,
        log_tag: &str,
    ) -> Result<(), TimeoutOr<ConnectError<TransportConnectError>>> {
        let Self {
            connect_state,
            dns_resolver,
            network_change_event,
            confirmation_header_name: _,
        } = self;

        let ConnectStateSnapshot {
            route_resolver,
            connect_timeout,
            network_interface_poll_interval,
            post_route_change_connect_timeout,
            transport_connector,
            attempts_record,
            route_provider_context,
        } = connect_state
            .lock()
            .expect("not poisoned")
            .prepare_snapshot::<UsePreconnect<_>>();

        let routes = routes
            .map_routes(|r| UsePreconnect {
                should: true,
                inner: r,
            })
            .routes(&route_provider_context)
            .collect_vec();

        log::info!(
            "[{log_tag}] starting connection attempt with {} routes",
            routes.len()
        );

        struct ConnectWithSavedRoute<C>(C);

        impl<R, Inner, C> Connector<R, Inner> for ConnectWithSavedRoute<C>
        where
            C: Connector<R, Inner>,
            R: Clone + Send,
        {
            type Connection = (R, C::Connection);

            type Error = C::Error;

            fn connect_over(
                &self,
                over: Inner,
                route: R,
                log_tag: &str,
            ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
                self.0
                    .connect_over(over, route.clone(), log_tag)
                    .map_ok(|connection| (route, connection))
            }
        }

        let route_provider = routes.into_iter();
        let connector = InterfaceMonitor::new(
            ConnectWithSavedRoute(&transport_connector),
            network_change_event.clone(),
            network_interface_poll_interval,
            post_route_change_connect_timeout,
        );
        let delay_policy = DelayBasedOnTransport(attempts_record);

        let start = Instant::now();
        let connect = crate::infra::route::connect(
            &route_resolver,
            delay_policy,
            route_provider,
            dns_resolver,
            connector,
            (),
            log_tag,
            |error| {
                match error {
                    InterfaceChangedOr::InterfaceChanged => {
                        ControlFlow::Break(TransportConnectError::ClientAbort)
                    }
                    InterfaceChangedOr::Other(_) => {
                        // All normal transport-level errors are considered intermittent; see
                        // WebSocketServiceConnectError::classify.
                        ControlFlow::Continue(())
                    }
                }
            },
        );

        let (result, updates) = tokio::time::timeout(connect_timeout, connect)
            .await
            .map_err(|_: tokio::time::error::Elapsed| TimeoutOr::Timeout {
                attempt_duration: connect_timeout,
            })?;

        match &result {
            Ok(_) => {
                // We can't log the route here because we don't require DescribeForLog.
                // That's okay, though, it's not critical.
                log::info!(
                    "[{log_tag}] connection succeeded after {:.3?}",
                    updates.finished_at - start
                );
            }
            Err(e) => log::info!("[{log_tag}] connection failed with {e}"),
        }

        // Don't exit yet, we have to save the results!
        {
            let mut connect_write = connect_state.lock().expect("not poisoned");

            connect_write.attempts_record.apply_outcome_updates(
                updates
                    .outcomes
                    .into_iter()
                    .map(|(route, outcome)| (route.into_transport_part(), outcome)),
                updates.finished_at,
                SystemTime::now(),
            );

            let (
                UsePreconnect {
                    inner: route,
                    should: _,
                },
                connection,
            ) = result?;

            connect_write.make_transport_connector.save_preconnected(
                route,
                connection,
                updates.finished_at,
            );
        }

        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
struct RouteProviderContextImpl(UnwrapErr<OsRng>);

impl RouteProviderContext for RouteProviderContextImpl {
    fn random_usize(&self) -> usize {
        // OsRng is zero-sized, so we're not losing random values by copying it.
        let mut owned_rng: UnwrapErr<OsRng> = self.0;
        assert_eq_size_val!(owned_rng, ());
        UniformUsize::sample_single_inclusive(0, usize::MAX, &mut owned_rng).expect("valid range")
    }
}

/// Convenience alias for using `PreconnectingConnector`s with [`ConnectState`].
pub type PreconnectingFactory<Inner = DefaultConnectorFactory> =
    libsignal_net_infra::route::PreconnectingFactory<TransportRoute, Inner>;

pub fn infer_proxy_mode_for_config(config: ConnectionProxyConfig) -> DirectOrProxyMode {
    if config.is_signal_transparent_proxy() {
        // This was configured in the app, we should take it as a requirement.
        DirectOrProxyMode::ProxyOnly(config)
    } else {
        // This was set at the system level or provided as an environment variable, it may not have
        // been intended to apply to Signal.
        DirectOrProxyMode::ProxyThenDirect(config)
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::sync::{Arc, LazyLock, Mutex};
    use std::time::Duration;

    use assert_matches::assert_matches;
    use const_str::ip_addr;
    use http::HeaderMap;
    use http::uri::PathAndQuery;
    use libsignal_net_infra::certs::RootCertificates;
    use libsignal_net_infra::dns::lookup_result::LookupResult;
    use libsignal_net_infra::host::Host;
    use libsignal_net_infra::route::testutils::ConnectFn;
    use libsignal_net_infra::route::{
        AttemptOutcome, DirectOrProxyRoute, HAPPY_EYEBALLS_DELAY, HttpVersion, HttpsTlsRoute,
        TcpRoute, TlsRoute, TlsRouteFragment, UnresolvedHost, UnresolvedTransportRoute,
        UnsuccessfulOutcome, WebSocketRoute,
    };
    use libsignal_net_infra::utils::no_network_change_events;
    use libsignal_net_infra::{Alpn, OverrideNagleAlgorithm, RouteType};
    use nonzero_ext::nonzero;

    use super::*;
    use crate::ws::NotRejectedByServer;

    const FAKE_HOST_NAME: &str = "direct-host";
    static FAKE_TRANSPORT_ROUTE: LazyLock<UnresolvedTransportRoute> = LazyLock::new(|| TlsRoute {
        fragment: TlsRouteFragment {
            root_certs: RootCertificates::Native,
            sni: Host::Domain("fake-sni".into()),
            alpn: Some(Alpn::Http1_1),
            min_protocol_version: Some(boring_signal::ssl::SslVersion::TLS1_3),
        },
        inner: DirectOrProxyRoute::Direct(TcpRoute {
            address: UnresolvedHost::from(Arc::from(FAKE_HOST_NAME)),
            port: nonzero!(1234u16),
            override_nagle_algorithm: OverrideNagleAlgorithm::UseSystemDefault,
        }),
    });
    static FAKE_WEBSOCKET_ROUTES: LazyLock<[UnresolvedWebsocketServiceRoute; 2]> =
        LazyLock::new(|| {
            [
                WebSocketRoute {
                    fragment: WebSocketRouteFragment {
                        ws_config: Default::default(),
                        endpoint: PathAndQuery::from_static("/first"),
                        headers: HeaderMap::new(),
                    },
                    inner: HttpsTlsRoute {
                        fragment: HttpRouteFragment {
                            host_header: "first-host".into(),
                            path_prefix: "".into(),
                            http_version: Some(HttpVersion::Http1_1),
                            front_name: None,
                        },
                        inner: (*FAKE_TRANSPORT_ROUTE).clone(),
                    },
                },
                WebSocketRoute {
                    fragment: WebSocketRouteFragment {
                        ws_config: Default::default(),
                        endpoint: PathAndQuery::from_static("/second"),
                        headers: HeaderMap::new(),
                    },
                    inner: HttpsTlsRoute {
                        fragment: HttpRouteFragment {
                            host_header: "second-host".into(),
                            path_prefix: "".into(),
                            http_version: Some(HttpVersion::Http1_1),
                            front_name: Some(RouteType::ProxyF.into()),
                        },
                        inner: (*FAKE_TRANSPORT_ROUTE).clone(),
                    },
                },
            ]
        });

    #[tokio::test(start_paused = true)]
    async fn connect_ws_successful() {
        // This doesn't actually matter since we're using a fake connector, but
        // using the real route type is easier than trying to add yet more
        // generic parameters.
        let [failing_route, succeeding_route] = (*FAKE_WEBSOCKET_ROUTES).clone();

        let ws_connector = ConnectFn(|(), route| {
            let (ws, http) = &route;
            std::future::ready(
                if (ws, http) == (&failing_route.fragment, &failing_route.inner.fragment) {
                    Err(tungstenite::Error::ConnectionClosed.into())
                } else {
                    Ok(route)
                },
            )
        });
        let resolver = DnsResolver::new_from_static_map(HashMap::from([(
            FAKE_HOST_NAME,
            LookupResult::new(vec![ip_addr!(v4, "192.0.2.1")], vec![]),
        )]));

        let fake_transport_connector =
            ConnectFn(move |(), _| std::future::ready(Ok::<_, WebSocketConnectError>(())));

        let state = ConnectState {
            connect_timeout: Duration::MAX,
            network_interface_poll_interval: Duration::MAX,
            post_route_change_connect_timeout: Duration::MAX,
            route_resolver: RouteResolver::default(),
            attempts_record: ConnectionOutcomes::new(SUGGESTED_CONNECT_PARAMS),
            make_transport_connector: fake_transport_connector,
            route_provider_context: Default::default(),
        }
        .into();

        let connection_resources = ConnectionResources {
            connect_state: &state,
            dns_resolver: &resolver,
            network_change_event: &no_network_change_events(),
            confirmation_header_name: None,
        };

        let result = connection_resources
            .connect_ws(
                vec![failing_route.clone(), succeeding_route.clone()],
                ws_connector,
                "test",
            )
            // This previously hung forever due to a deadlock bug.
            .await;

        let (connection, info) = result.expect("succeeded");
        assert_eq!(
            connection,
            (succeeding_route.fragment, succeeding_route.inner.fragment)
        );
        let RouteInfo { unresolved } = info;

        assert_eq!(unresolved.to_string(), "REDACTED:1234 fronted by proxyf");
    }

    #[tokio::test(start_paused = true)]
    async fn connect_ws_timeout() {
        let ws_connector = <crate::infra::ws::Stateless>::default();
        let resolver = DnsResolver::new_from_static_map(HashMap::from([(
            FAKE_HOST_NAME,
            LookupResult::new(vec![ip_addr!(v4, "192.0.2.1")], vec![]),
        )]));

        let always_hangs_connector = ConnectFn(|(), _| {
            std::future::pending::<Result<tokio::io::DuplexStream, WebSocketConnectError>>()
        });

        const CONNECT_TIMEOUT: Duration = Duration::from_secs(31);

        let state = ConnectState {
            connect_timeout: CONNECT_TIMEOUT,
            network_interface_poll_interval: Duration::MAX,
            post_route_change_connect_timeout: Duration::MAX,
            route_resolver: RouteResolver::default(),
            attempts_record: ConnectionOutcomes::new(SUGGESTED_CONNECT_PARAMS),
            make_transport_connector: always_hangs_connector,
            route_provider_context: Default::default(),
        }
        .into();

        let [failing_route, succeeding_route] = (*FAKE_WEBSOCKET_ROUTES).clone();

        let connection_resources = ConnectionResources {
            connect_state: &state,
            dns_resolver: &resolver,
            network_change_event: &no_network_change_events(),
            confirmation_header_name: None,
        };

        let connect = connection_resources.connect_ws(
            vec![failing_route.clone(), succeeding_route.clone()],
            ws_connector,
            "test",
        );

        let start = Instant::now();
        let result: Result<_, TimeoutOr<ConnectError<_>>> = connect.await;

        assert_matches!(
            result,
            Err(TimeoutOr::Timeout {
                attempt_duration: CONNECT_TIMEOUT
            })
        );
        assert_eq!(start.elapsed(), CONNECT_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn client_abort_transport_error_is_fatal() {
        // We can't directly test the ClientAbort produced for a network change without *more*
        // custom dependency injection for connect_ws---we can fire the network change event, but we
        // can't actually change the local IP detection logic. But we can test a ClientAbort
        // produced by the underlying connector.

        let ws_connector = <crate::infra::ws::Stateless>::default();
        let resolver = DnsResolver::new_from_static_map(HashMap::from([(
            FAKE_HOST_NAME,
            LookupResult::new(vec![ip_addr!(v4, "192.0.2.1")], vec![]),
        )]));

        let client_abort_connector = ConnectFn(|(), _| {
            std::future::ready(Err::<tokio::io::DuplexStream, _>(
                TransportConnectError::ClientAbort,
            ))
        });

        const CONNECT_TIMEOUT: Duration = Duration::from_secs(31);

        let state = ConnectState {
            connect_timeout: CONNECT_TIMEOUT,
            network_interface_poll_interval: Duration::MAX,
            post_route_change_connect_timeout: Duration::MAX,
            route_resolver: RouteResolver::default(),
            attempts_record: ConnectionOutcomes::new(SUGGESTED_CONNECT_PARAMS),
            make_transport_connector: client_abort_connector,
            route_provider_context: Default::default(),
        }
        .into();

        let [failing_route, succeeding_route] = (*FAKE_WEBSOCKET_ROUTES).clone();

        let connection_resources = ConnectionResources {
            connect_state: &state,
            dns_resolver: &resolver,
            network_change_event: &no_network_change_events(),
            confirmation_header_name: None,
        };

        let connect = connection_resources.connect_ws(
            vec![failing_route.clone(), succeeding_route.clone()],
            ws_connector,
            "test",
        );

        let result: Result<_, TimeoutOr<ConnectError<_>>> = connect.await;

        assert_matches!(
            result,
            Err(TimeoutOr::Other(ConnectError::FatalConnect(
                WebSocketServiceConnectError::Connect(
                    WebSocketConnectError::Transport(TransportConnectError::ClientAbort),
                    NotRejectedByServer { .. }
                )
            )))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn cooldowns_reset_on_network_change_even_during_connect() {
        // This doesn't actually matter since we're using a fake connector, but
        // using the real route type is easier than trying to add yet more
        // generic parameters.
        let route = FAKE_WEBSOCKET_ROUTES[0].clone();
        let start = Instant::now();

        let ws_connector = ConnectFn(|(), route| std::future::ready(Ok(route)));
        let bad_ip = ip_addr!(v4, "192.0.2.1");
        let good_ip = ip_addr!(v4, "192.0.2.2");
        let resolver = DnsResolver::new_from_static_map(HashMap::from([(
            FAKE_HOST_NAME,
            LookupResult::new(vec![bad_ip, good_ip], vec![]),
        )]));

        let fake_transport_connector = ConnectFn(move |(), route: TransportRoute| {
            std::future::ready(if *route.immediate_target() == bad_ip {
                Err(TransportConnectError::TcpConnectionFailed)
            } else {
                Ok(())
            })
        });

        let mut state = ConnectState {
            connect_timeout: Duration::MAX,
            network_interface_poll_interval: Duration::MAX,
            post_route_change_connect_timeout: Duration::MAX,
            route_resolver: RouteResolver::default(),
            attempts_record: ConnectionOutcomes::new(SUGGESTED_CONNECT_PARAMS),
            make_transport_connector: fake_transport_connector,
            route_provider_context: Default::default(),
        };

        let past_failure = AttemptOutcome {
            started: start,
            result: Err(UnsuccessfulOutcome::default()),
        };
        state.attempts_record.apply_outcome_updates(
            [
                (
                    route.transport_part().clone().resolve(|_| bad_ip.into()),
                    past_failure,
                ),
                (
                    route.transport_part().clone().resolve(|_| good_ip.into()),
                    past_failure,
                ),
            ],
            start,
            SystemTime::now(),
        );

        let (network_change_tx, network_change_rx) = tokio::sync::watch::channel(());

        let connection_resources = ConnectionResources {
            connect_state: &state.into(),
            dns_resolver: &resolver,
            network_change_event: &network_change_rx,
            confirmation_header_name: None,
        };

        let mut connect = std::pin::pin!(connection_resources.connect_ws(
            vec![route.clone()],
            ws_connector,
            "test",
        ));

        let network_change_delay = Duration::from_millis(500);
        _ = tokio::time::timeout(network_change_delay, connect.as_mut())
            .await
            .expect_err("should not be ready yet");

        network_change_tx.send_replace(());
        let result = connect.await;

        let (connection, _info) = result.expect("succeeded");
        assert_eq!(connection, (route.fragment, route.inner.fragment));
        assert_eq!(start.elapsed(), network_change_delay + HAPPY_EYEBALLS_DELAY);
    }

    #[tokio::test(start_paused = true)]
    async fn connect_h2_successful() {
        // This doesn't actually matter since we're using a fake connector, but
        // using the real route type is easier than trying to add yet more
        // generic parameters.
        let [failing_route, succeeding_route] = (*FAKE_WEBSOCKET_ROUTES).clone();

        let h2_connector = ConnectFn(|(), route| {
            std::future::ready(if route == failing_route.inner.fragment {
                Err(HttpConnectError::HttpHandshake)
            } else {
                Ok(route)
            })
        });
        let resolver = DnsResolver::new_from_static_map(HashMap::from([(
            FAKE_HOST_NAME,
            LookupResult::new(vec![ip_addr!(v4, "192.0.2.1")], vec![]),
        )]));

        let fake_transport_connector =
            ConnectFn(move |(), _| std::future::ready(Ok::<_, HttpConnectError>(())));

        let state = ConnectState {
            connect_timeout: Duration::MAX,
            network_interface_poll_interval: Duration::MAX,
            post_route_change_connect_timeout: Duration::MAX,
            route_resolver: RouteResolver::default(),
            attempts_record: ConnectionOutcomes::new(SUGGESTED_CONNECT_PARAMS),
            make_transport_connector: fake_transport_connector,
            route_provider_context: Default::default(),
        }
        .into();

        let connection_resources = ConnectionResources {
            connect_state: &state,
            dns_resolver: &resolver,
            network_change_event: &no_network_change_events(),
            confirmation_header_name: None,
        };

        let result = connection_resources
            .connect_h2(
                vec![failing_route.inner.clone(), succeeding_route.inner.clone()],
                h2_connector,
                "test",
            )
            // This previously hung forever due to a deadlock bug.
            .await;

        let (connection, info) = result.expect("succeeded");
        assert_eq!(connection, succeeding_route.inner.fragment);
        let RouteInfo { unresolved } = info;

        assert_eq!(unresolved.to_string(), "REDACTED:1234 fronted by proxyf");
    }

    #[tokio::test(start_paused = true)]
    async fn client_abort_transport_error_is_fatal_for_h2() {
        // We can't directly test the ClientAbort produced for a network change without *more*
        // custom dependency injection for connect_h2---we can fire the network change event, but we
        // can't actually change the local IP detection logic. But we can test a ClientAbort
        // produced by the underlying connector.

        let h2_connector = ConnectFn(|_, _| -> std::future::Pending<Result<(), _>> {
            unreachable!("transport should fail to connect")
        });
        let resolver = DnsResolver::new_from_static_map(HashMap::from([(
            FAKE_HOST_NAME,
            LookupResult::new(vec![ip_addr!(v4, "192.0.2.1")], vec![]),
        )]));

        let client_abort_connector = ConnectFn(|(), _| {
            std::future::ready(Err::<tokio::io::DuplexStream, _>(
                TransportConnectError::ClientAbort,
            ))
        });

        const CONNECT_TIMEOUT: Duration = Duration::from_secs(31);

        let state = ConnectState {
            connect_timeout: CONNECT_TIMEOUT,
            network_interface_poll_interval: Duration::MAX,
            post_route_change_connect_timeout: Duration::MAX,
            route_resolver: RouteResolver::default(),
            attempts_record: ConnectionOutcomes::new(SUGGESTED_CONNECT_PARAMS),
            make_transport_connector: client_abort_connector,
            route_provider_context: Default::default(),
        }
        .into();

        let [failing_route, succeeding_route] = (*FAKE_WEBSOCKET_ROUTES).clone();

        let connection_resources = ConnectionResources {
            connect_state: &state,
            dns_resolver: &resolver,
            network_change_event: &no_network_change_events(),
            confirmation_header_name: None,
        };

        let connect = connection_resources.connect_h2(
            vec![failing_route.inner.clone(), succeeding_route.inner.clone()],
            h2_connector,
            "test",
        );

        let result: Result<_, TimeoutOr<ConnectError<_>>> = connect.await;

        assert_matches!(
            result,
            Err(TimeoutOr::Other(ConnectError::FatalConnect(
                HttpConnectError::Transport(TransportConnectError::ClientAbort),
            )))
        );
    }

    mod outcome_processing {
        use std::net::Ipv4Addr;
        use std::num::NonZero;

        use UnsuccessfulOutcome::*;
        use libsignal_net_infra::route::{ConnectionProxyRoute, ProxyTarget, SocksRoute};
        use libsignal_net_infra::tcp_ssl::proxy::socks;
        use test_case::test_case;

        use super::*;

        #[derive(Clone, Copy, Debug)]
        enum OutcomeTestCase {
            DirectSuccess,
            DirectFailure,
            ProxySuccess,
            ProxyFailure,
        }
        use OutcomeTestCase::*;

        impl OutcomeTestCase {
            fn make(
                self,
                port: NonZero<u16>,
                started: Instant,
            ) -> (TransportRoute, AttemptOutcome) {
                let route = TlsRoute {
                    fragment: FAKE_TRANSPORT_ROUTE.fragment.clone(),
                    inner: match self {
                        DirectSuccess | DirectFailure => DirectOrProxyRoute::Direct(TcpRoute {
                            address: ip_addr!("192.0.2.1"),
                            port,
                            override_nagle_algorithm: OverrideNagleAlgorithm::UseSystemDefault,
                        }),
                        ProxySuccess | ProxyFailure => {
                            DirectOrProxyRoute::Proxy(ConnectionProxyRoute::Socks(SocksRoute {
                                proxy: TcpRoute {
                                    address: Ipv4Addr::LOCALHOST.into(),
                                    port: nonzero!(1080u16),
                                    override_nagle_algorithm:
                                        OverrideNagleAlgorithm::UseSystemDefault,
                                },
                                target_addr: ProxyTarget::ResolvedLocally(ip_addr!("192.0.2.1")),
                                target_port: port,
                                protocol: socks::Protocol::Socks5 {
                                    username_password: None,
                                },
                            }))
                        }
                    },
                };
                let outcome = AttemptOutcome {
                    started,
                    result: match self {
                        DirectSuccess | ProxySuccess => Ok(()),
                        DirectFailure | ProxyFailure => Err(UnsuccessfulOutcome::default()),
                    },
                };
                (route, outcome)
            }
        }

        #[test_case([DirectFailure, DirectFailure, ProxyFailure, ProxyFailure] => [Err(ShortTerm), Err(ShortTerm), Err(ShortTerm), Err(ShortTerm)])]
        #[test_case([DirectSuccess, DirectFailure, ProxyFailure, ProxyFailure] => [Ok(()), Err(ShortTerm), Err(LongTerm), Err(LongTerm)])]
        #[test_case([ProxyFailure, ProxyFailure, DirectFailure, DirectSuccess] => [Err(LongTerm), Err(LongTerm), Err(ShortTerm), Ok(())])]
        #[test_case([ProxyFailure, ProxySuccess, DirectFailure, DirectFailure] => [Err(ShortTerm), Ok(()), Err(ShortTerm), Err(ShortTerm)])]
        #[test_case([ProxyFailure, ProxySuccess, DirectFailure, DirectSuccess] => [Err(ShortTerm), Ok(()), Err(ShortTerm), Ok(())])]
        #[test_case([DirectFailure, DirectSuccess, ProxyFailure, ProxySuccess] => [Err(ShortTerm), Ok(()), Err(ShortTerm), Ok(())])]
        fn outcome_processing_long_term_vs_short_term<const N: usize>(
            outcomes: [OutcomeTestCase; N],
        ) -> [Result<(), UnsuccessfulOutcome>; N] {
            let now = Instant::now();
            let outcomes = outcomes
                .into_iter()
                .zip(1..)
                .map(|(test_case, port)| test_case.make(port.try_into().expect("non-zero"), now))
                .collect_vec();
            process_outcomes(outcomes)
                .map(|(_route, outcome)| outcome.result)
                .collect_array()
                .unwrap()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn preconnect_records_outcomes() {
        let ws_connector = ConnectFn(|(), route| std::future::ready(Ok(route)));
        let resolver = DnsResolver::new_from_static_map(HashMap::from([(
            FAKE_HOST_NAME,
            LookupResult::new(vec![ip_addr!(v4, "192.0.2.1")], vec![]),
        )]));

        let attempts_by_host = Mutex::new(HashMap::<Host<_>, u32>::new());
        let make_transport_connector = PreconnectingFactory::new(
            ConnectFn(|(), route: TransportRoute| {
                let host = route.fragment.sni;
                let result = if host == Host::parse_as_ip_or_domain("fail") {
                    Err(TransportConnectError::TcpConnectionFailed)
                } else {
                    Ok(())
                };
                *attempts_by_host
                    .lock()
                    .expect("no panic")
                    .entry(host)
                    .or_default() += 1;
                std::future::ready(result)
            }),
            Duration::from_secs(60),
        );

        const CONNECT_TIMEOUT: Duration = Duration::from_secs(31);

        let state = ConnectState {
            connect_timeout: CONNECT_TIMEOUT,
            network_interface_poll_interval: Duration::MAX,
            post_route_change_connect_timeout: Duration::MAX,
            route_resolver: RouteResolver::default(),
            attempts_record: ConnectionOutcomes::new(SUGGESTED_CONNECT_PARAMS),
            make_transport_connector,
            route_provider_context: Default::default(),
        }
        .into();

        let good_transport_route = FAKE_TRANSPORT_ROUTE.clone();
        let mut bad_transport_route = good_transport_route.clone();
        bad_transport_route.fragment.sni = Host::parse_as_ip_or_domain("fail");

        let connection_resources = ConnectionResources {
            connect_state: &state,
            dns_resolver: &resolver,
            network_change_event: &no_network_change_events(),
            confirmation_header_name: None,
        };

        connection_resources
            .preconnect_and_save(
                vec![bad_transport_route.clone(), good_transport_route.clone()],
                "preconnect",
            )
            .await
            .expect("success");

        assert_eq!(
            *attempts_by_host.lock().expect("not poisoned"),
            HashMap::from_iter([
                (Host::parse_as_ip_or_domain("fake-sni"), 1),
                (Host::parse_as_ip_or_domain("fail"), 1),
            ])
        );

        let connection_resources = ConnectionResources {
            connect_state: &state,
            dns_resolver: &resolver,
            network_change_event: &no_network_change_events(),
            confirmation_header_name: None,
        };

        _ = connection_resources
            .connect_ws(
                [bad_transport_route.clone(), good_transport_route.clone()]
                    .into_iter()
                    .map(|route| WebSocketRoute {
                        fragment: WebSocketRouteFragment {
                            ws_config: Default::default(),
                            endpoint: PathAndQuery::from_static("/"),
                            headers: HeaderMap::new(),
                        },
                        inner: HttpsTlsRoute {
                            fragment: HttpRouteFragment {
                                host_header: "host".into(),
                                path_prefix: "".into(),
                                http_version: Some(HttpVersion::Http1_1),
                                front_name: None,
                            },
                            inner: route,
                        },
                    })
                    .collect_vec(),
                ws_connector,
                "test",
            )
            .await
            .expect("succeeded");

        // Even though the bad transport route was listed first, we should have tried the good
        // transport route first due to the record of the preconnect attempts.
        assert_eq!(
            *attempts_by_host.lock().expect("not poisoned"),
            HashMap::from_iter([
                (Host::parse_as_ip_or_domain("fake-sni"), 2),
                (Host::parse_as_ip_or_domain("fail"), 1),
            ])
        );
    }
}
