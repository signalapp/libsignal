//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::hash::Hash;
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;

use futures_util::stream::{FusedStream, FuturesUnordered};
use futures_util::{FutureExt, StreamExt};
use tokio::time::Instant;
use tokio_util::either::Either;

use crate::errors::LogSafeDisplay;
use crate::host::Host;
use crate::utils::future::SomeOrPending;

mod connect;
pub use connect::*;

mod describe;
pub use describe::*;

mod http;
pub use http::*;

pub mod provider;
pub use crate::route::provider::RouteProviderExt;

mod proxy;
pub use proxy::*;

mod resolve;
pub use resolve::*;

mod schedule;
pub use schedule::*;

mod tcp;
pub use tcp::*;

mod tls;
pub use tls::*;

mod ws;
pub use ws::*;

/// How long to hold back a route that gets resolved before its predecessor
/// before trying to connect with it anyway.
const OUT_OF_ORDER_RESOLUTION_DEBOUNCE_TIME: Duration = Duration::from_secs(5);

/// Produces routes to a destination.
///
/// A "route" here is a path to a target destination of some kind. It does not
/// have to be fully-specified but it does contain information about how to
/// reach a remote target.
pub trait RouteProvider {
    /// The type of route being produced.
    type Route;

    /// Produces a sequence of routes in priority order.
    ///
    /// The routes must be produced in the order in which connection attempts
    /// should be made. The iterator is allowed to borrow from `self` as an
    /// optimization.
    ///
    /// Why is `context` a `&` instead of a `&mut`? Because as of Jan 2025,
    /// there's no way to prevent the lifetime in the type of `context` from
    /// being captured in the opaque return type. That's important because there
    /// are some implementations of this trait where it's necessary to combine
    /// the output of two different comprising providers. If `context` was a
    /// `&mut` the first call's exclusive borrow for its entire lifetime would
    /// prevent the second call from being able to use the same `context`.
    ///
    /// There are two potential ways we could work around this:
    ///
    /// 1. Use the new precise-capture syntax introduced in Rust 1.82. This
    ///    isn't an option now because that syntax isn't supported in trait
    ///    methods. Once <https://github.com/rust-lang/rust/issues/130044> is
    ///    stabilized and available (per our MSRV) we can revisit this.
    ///
    /// 2. Introduce a named associated type that only captures `'s`, not `'c`.
    ///    This works now, but would require all returned iterator types to be
    ///    named. That would prevent us from using `Iterator::map` and other
    ///    combinators, or require any uses be `Box`ed and those tradeoffs
    ///    aren't (currently) worth the imprecision.
    fn routes<'s>(
        &'s self,
        context: &impl RouteProviderContext,
    ) -> impl Iterator<Item = Self::Route> + 's;
}

/// Context parameter passed to [`RouteProvider::routes`].
///
/// This provides methods and access to mutable state that a `RouteProvider`
/// implementer can use to make decisions about what routes to emit.
pub trait RouteProviderContext {
    /// Returns a uniformly random [`usize`].
    fn random_usize(&self) -> usize;
}

/// A hostname in a route that can later be resolved to IP addresses.
#[derive(Clone, Debug, PartialEq, Eq, Hash, derive_more::From, derive_more::Into)]
pub struct UnresolvedHost(pub Arc<str>);

/// Allows replacing part of a route.
///
/// The value being replaced has type `F` and the replacement type is determined
/// by the caller.
pub trait ReplaceFragment<F> {
    /// The type of the new value after replacing `F` with a value of type `T`.
    type Replacement<T>;

    /// Replace a value of type `F` in `Self` with a value of type `T`.
    ///
    /// The callback constructs a value of type `T` given the former `F` value.
    fn replace<T>(self, make_fragment: impl FnOnce(F) -> T) -> Self::Replacement<T>;
}

/// Generic route type that stacks a protocol-specific fragment on top of an
/// inner route.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct SimpleRoute<Fragment, Inner> {
    /// The protocol-specific information for this route.
    pub fragment: Fragment,
    /// The lower-level route value.
    pub inner: Inner,
}

/// Transport-level route that contains [`UnresolvedHost`] addresses.
pub type UnresolvedTransportRoute = TlsRoute<
    DirectOrProxyRoute<TcpRoute<UnresolvedHost>, ConnectionProxyRoute<Host<UnresolvedHost>>>,
>;
/// [`HttpsTlsRoute`] that contains [`UnresolvedHost`] addresses.
pub type UnresolvedHttpsServiceRoute = HttpsTlsRoute<UnresolvedTransportRoute>;

/// [`WebSocketRoute`] that contains [`UnresolvedHost`] addresses.
pub type UnresolvedWebsocketServiceRoute = WebSocketRoute<HttpsTlsRoute<UnresolvedTransportRoute>>;

/// Transport-level route that contains [`IpAddr`]s.
pub type TransportRoute =
    TlsRoute<DirectOrProxyRoute<TcpRoute<IpAddr>, ConnectionProxyRoute<IpAddr>>>;
/// [`HttpsTlsRoute`] that contains [`IpAddr`]s.
pub type HttpsServiceRoute = HttpsTlsRoute<TransportRoute>;
/// [`WebSocketRoute`] that contains [`IpAddr`]s.
pub type WebSocketServiceRoute = WebSocketRoute<HttpsServiceRoute>;

/// Error for [`connect()`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectError<E> {
    /// The route provider did not produce any routes.
    NoResolvedRoutes,
    /// All attempts to connect failed, but none fatally.
    AllAttemptsFailed,
    /// An attempt to connect failed fatally.
    FatalConnect(E),
}

/// Recorded success and failure information from [`connect()`].
///
/// This should be used to update the internal state of the delay policy after
/// the connection attempt completes.
#[must_use]
#[derive(Debug, PartialEq)]
pub struct OutcomeUpdates<R> {
    /// A list of routes for which connection attempts finished, and the
    /// respective statuses.
    pub outcomes: Vec<(R, AttemptOutcome)>,
    /// The time at which the connect attempt finished.
    pub finished_at: Instant,
}

/// Attempt to connect to routes from the given [`RouteProvider`].
///
/// Generates the sequence of routes from the given `RouteProvider` and then
/// attempts to connect to them. The order in which connetion attempts are made
/// depends on recorded state from previous connection attempts and the order in
/// which the unresolved routes get resolved. The first successful connection
/// attempt is returned, along with a set of updates that should be used to
/// update the provided `RouteDelayPolicy` implementer.
///
/// When a connection attempt fails, the error is passed to the provided
/// callback to determine whether it is severe enough to fail the entire
/// connection attempt. An example of such a fatal error would be if the remote
/// server is reachable but immediately closes the connection with an HTTP 4xx
/// error.
///
/// The `Future` returned by this function resolves when all connection attempts
/// are exhausted or a one of them produces a fatal error.
pub async fn connect<R, UR, C, Inner, FatalError>(
    route_resolver: &RouteResolver,
    delay_policy: impl RouteDelayPolicy<R>,
    ordered_routes: impl Iterator<Item = UR>,
    resolver: &impl Resolver,
    connector: C,
    inner: Inner,
    log_tag: Arc<str>,
    on_error: impl FnMut(C::Error) -> ControlFlow<FatalError>,
) -> (
    Result<C::Connection, ConnectError<FatalError>>,
    OutcomeUpdates<R>,
)
where
    Inner: Clone,
    C: Connector<R, Inner>,
    UR: ResolveHostnames<Resolved = R> + Clone + 'static,
    R: Clone + ResolvedRoute,
{
    let resolver_stream = route_resolver.resolve(ordered_routes, resolver);

    connect_inner(
        resolver_stream,
        delay_policy,
        connector,
        inner,
        log_tag,
        on_error,
    )
    .await
}

/// Like [`connect`] but takes a collection of resolved routes.
///
/// The resolved routes are assumed to all be the result of resolving a single
/// unresolved route.
pub async fn connect_resolved<R, C, Inner, FatalError>(
    routes: Vec<R>,
    delay_policy: impl RouteDelayPolicy<R>,
    connector: C,
    inner: Inner,
    log_tag: Arc<str>,
    on_error: impl FnMut(C::Error) -> ControlFlow<FatalError>,
) -> (
    Result<C::Connection, ConnectError<FatalError>>,
    OutcomeUpdates<R>,
)
where
    Inner: Clone,
    C: Connector<R, Inner>,
    R: Clone + ResolvedRoute,
{
    connect_inner(
        futures_util::stream::once(std::future::ready(schedule::as_resolved_group(routes))),
        delay_policy,
        connector,
        inner,
        log_tag,
        on_error,
    )
    .await
}

async fn connect_inner<R, C, Inner, FatalError>(
    resolver_stream: impl FusedStream<Item = (ResolvedRoutes<R>, ResolveMeta)>,
    delay_policy: impl RouteDelayPolicy<R>,
    connector: C,
    inner: Inner,
    log_tag: Arc<str>,
    mut on_error: impl FnMut(C::Error) -> ControlFlow<FatalError>,
) -> (
    Result<C::Connection, ConnectError<FatalError>>,
    OutcomeUpdates<R>,
)
where
    R: Clone,
    Inner: Clone,
    C: Connector<R, Inner>,
{
    let schedule = Some(Schedule::new(
        resolver_stream,
        delay_policy,
        OUT_OF_ORDER_RESOLUTION_DEBOUNCE_TIME,
    ));
    let mut schedule = std::pin::pin!(schedule);

    let mut sleep_until_start_next_connection = tokio::time::sleep(Duration::ZERO);
    let mut sleep_until_start_next_connection = std::pin::pin!(sleep_until_start_next_connection);

    // Every N seconds, log about what we've tried and still have yet to try.
    let mut log_for_slow_connections = tokio::time::interval(Duration::from_secs(3));
    log_for_slow_connections.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    // Whether the Schedule should be polled for its next route.
    let mut poll_schedule_for_next = true;
    let mut most_recent_connection_start = Instant::now();
    let mut connects_in_progress = FuturesUnordered::new();
    let mut outcomes = Vec::new();

    #[derive(Debug)]
    enum Event<C, R> {
        StartNextConnection,
        ConnectionAttemptFinished(C),
        NextRouteAvailable(R),
        LogStatus,
    }

    let outcome = loop {
        // If there's still a Schedule to pull from, poll it for more routes
        // or sleep until that's supposed to start.
        let poll_or_wait = schedule.as_mut().as_pin_mut().map(|schedule| {
            if poll_schedule_for_next {
                Either::Left(schedule.next().map(Event::NextRouteAvailable))
            } else {
                Either::Right(
                    sleep_until_start_next_connection
                        .as_mut()
                        .map(|()| Event::StartNextConnection),
                )
            }
        });

        // Wait for the next in-progress connection attempt to finish, if
        // there are any
        let next_connect_in_progress = (!connects_in_progress.is_empty()).then(|| {
            connects_in_progress
                .next()
                .map(|o| o.expect("checked non-empty"))
        });

        // If there aren't any connection attempts in progress and there
        // also aren't gonna be any more, we've run out of possibilities.
        if poll_or_wait.is_none() && next_connect_in_progress.is_none() {
            break Err(ConnectError::AllAttemptsFailed);
        }

        let event = tokio::select! {
            event = SomeOrPending::from(poll_or_wait) => event,
            c = SomeOrPending::from(next_connect_in_progress) => Event::ConnectionAttemptFinished(c),
            _ = log_for_slow_connections.tick() => Event::LogStatus,
        };

        match event {
            Event::StartNextConnection => {
                poll_schedule_for_next = true;
            }

            Event::NextRouteAvailable(Some(route)) => {
                connects_in_progress.push(async {
                    let started = Instant::now();
                    let result = connector
                        .connect_over(inner.clone(), route.clone(), log_tag.clone())
                        .await;
                    (route, result, started)
                });
                poll_schedule_for_next = false;
                most_recent_connection_start = Instant::now();

                sleep_until_start_next_connection.as_mut().reset(
                    most_recent_connection_start + pull_next_route_delay(&connects_in_progress),
                );
            }
            Event::NextRouteAvailable(None) => {
                // The Schedule is empty, so make sure it's not polled again.
                schedule.set(None);
                poll_schedule_for_next = false;
            }
            Event::ConnectionAttemptFinished((route, result, started)) => {
                let make_outcome = |result| (route, AttemptOutcome { started, result });
                match result.map_err(&mut on_error) {
                    Ok(connection) => {
                        // We've got a successful connection!
                        outcomes.push(make_outcome(Ok(())));
                        break Ok(connection);
                    }
                    Err(ControlFlow::Continue(())) => {
                        // Record the non-fatal error outcome and move on.
                        outcomes.push(make_outcome(Err(UnsuccessfulOutcome)));
                    }
                    Err(ControlFlow::Break(fatal_err)) => {
                        // This isn't a route-level error, it's a
                        // service-level error. It doesn't necessarily mean
                        // the route is bad, so don't record the
                        // unsuccessful attempt.
                        break Err(ConnectError::FatalConnect(fatal_err));
                    }
                }

                // We probably now want to start the next connection sooner.
                sleep_until_start_next_connection.as_mut().reset(
                    most_recent_connection_start + pull_next_route_delay(&connects_in_progress),
                );
            }
            Event::LogStatus => {
                log::info!(
                    "[{log_tag}] {} connection(s) in progress, {} pending",
                    connects_in_progress.len(),
                    if schedule.is_some() { "more" } else { "none" }
                );
            }
        }
    };
    (
        outcome,
        OutcomeUpdates {
            outcomes,
            finished_at: Instant::now(),
        },
    )
}

impl<E: LogSafeDisplay> LogSafeDisplay for ConnectError<E> {}
impl<E: std::fmt::Display> std::fmt::Display for ConnectError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::NoResolvedRoutes => f.write_str("no resolved routes"),
            ConnectError::AllAttemptsFailed => f.write_str("all connect attempts failed"),
            ConnectError::FatalConnect(e) => write!(f, "fatal connect error: {e}"),
        }
    }
}

const PER_CONNECTION_WAIT_DURATION: Duration = Duration::from_millis(500);

fn pull_next_route_delay<F>(connects_in_progress: &FuturesUnordered<F>) -> Duration {
    let connections_factor = connects_in_progress.len().try_into().unwrap_or(u32::MAX);

    PER_CONNECTION_WAIT_DURATION * connections_factor
}

impl<R: RouteProvider> RouteProvider for &R {
    type Route = R::Route;

    fn routes<'s>(
        &'s self,
        context: &impl RouteProviderContext,
    ) -> impl Iterator<Item = Self::Route> + 's {
        R::routes(self, context)
    }
}

/// [`RouteDelayPolicy`] that always returns a delay of zero.
#[derive(Copy, Clone, Debug)]
pub struct NoDelay;

impl<R> RouteDelayPolicy<R> for NoDelay {
    fn compute_delay(&self, _route: &R, _now: Instant) -> Duration {
        Duration::ZERO
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod testutils {
    use std::cell::RefCell;
    use std::net::IpAddr;

    use rand::rngs::mock::StepRng;
    use rand::Rng as _;

    pub use super::connect::testutils::*;
    pub use super::resolve::testutils::*;
    use super::*;

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    pub struct FakeRoute<A>(pub A);

    impl<A: ResolveHostnames> ResolveHostnames for FakeRoute<A> {
        type Resolved = FakeRoute<A::Resolved>;

        fn hostnames(&self) -> impl Iterator<Item = &UnresolvedHost> {
            self.0.hostnames()
        }

        fn resolve(self, lookup: impl FnMut(&str) -> IpAddr) -> Self::Resolved {
            FakeRoute(self.0.resolve(lookup))
        }
    }

    impl<A: ResolvedRoute> ResolvedRoute for FakeRoute<A> {
        fn immediate_target(&self) -> &IpAddr {
            self.0.immediate_target()
        }
    }

    impl<R: Clone> RouteProvider for Vec<R> {
        type Route = R;

        fn routes<'s>(
            &'s self,
            _context: &impl RouteProviderContext,
        ) -> impl Iterator<Item = Self::Route> + 's {
            self.iter().cloned()
        }
    }

    pub struct FakeContext {
        rng: RefCell<StepRng>,
    }

    impl Default for FakeContext {
        fn default() -> Self {
            Self::new()
        }
    }

    impl FakeContext {
        pub fn new() -> Self {
            Self {
                // Randomly chosen initial and increment values.
                rng: StepRng::new(13618430565133050083, 8391096191305687941).into(),
            }
        }
    }

    impl RouteProviderContext for FakeContext {
        fn random_usize(&self) -> usize {
            self.rng.borrow_mut().gen()
        }
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::fmt::Debug;
    use std::future::Future;
    use std::net::{IpAddr, Ipv4Addr};
    use std::num::NonZeroU16;
    use std::sync::LazyLock;

    use ::http::uri::PathAndQuery;
    use ::http::HeaderMap;
    use assert_matches::assert_matches;
    use const_str::ip_addr;
    use futures_util::{Stream, StreamExt};
    use itertools::Itertools as _;
    use nonzero_ext::nonzero;
    use tokio::sync::{mpsc, oneshot};
    use tokio_stream::wrappers::UnboundedReceiverStream;
    use tungstenite::protocol::WebSocketConfig;

    use super::*;
    use crate::certs::RootCertificates;
    use crate::dns::lookup_result::LookupResult;
    use crate::host::Host;
    use crate::route::resolve::testutils::FakeResolver;
    use crate::route::testutils::{FakeContext, FakeRoute};
    use crate::route::{NoDelay, SocksProxy, TlsProxy};
    use crate::tcp_ssl::proxy::socks;
    use crate::{Alpn, DnsSource};

    static WS_ENDPOINT: LazyLock<PathAndQuery> =
        LazyLock::new(|| PathAndQuery::from_static("/ws-path"));
    const ROOT_CERTS: RootCertificates = RootCertificates::FromDer(Cow::Borrowed(b"cert"));
    const PROXY_ROOT_CERTS: RootCertificates = RootCertificates::FromDer(Cow::Borrowed(b"proxy"));

    #[test]
    fn websocket_routes() {
        const TARGET_PORT: NonZeroU16 = nonzero!(8765u16);

        let provider = WebSocketProvider {
            fragment: WebSocketRouteFragment {
                ws_config: WebSocketConfig::default(),
                headers: HeaderMap::default(),
                endpoint: WS_ENDPOINT.clone(),
            },
            inner: HttpsProvider {
                direct_host_header: "http-host".into(),
                direct_http_version: HttpVersion::Http1_1,
                domain_front: DomainFrontRouteProvider {
                    fronts: vec![DomainFrontConfig {
                        root_certs: PROXY_ROOT_CERTS,
                        http_host: "front-host".into(),
                        sni_list: vec!["front-sni1".into(), "front-sni2".into()],
                        path_prefix: "/front-host-path-prefix".into(),
                        front_name: "front-host",
                        return_routes_with_all_snis: true,
                    }],
                    http_version: HttpVersion::Http2,
                },
                inner: TlsRouteProvider {
                    sni: Host::Domain("sni-name".into()),
                    certs: ROOT_CERTS.clone(),
                    inner: DirectTcpRouteProvider {
                        dns_hostname: "target-host".into(),
                        port: TARGET_PORT,
                    },
                },
            },
        };

        let routes = RouteProvider::routes(&provider, &FakeContext::new()).collect_vec();

        let expected_routes = vec![
            WebSocketRoute {
                fragment: WebSocketRouteFragment {
                    ws_config: WebSocketConfig::default(),
                    headers: HeaderMap::default(),
                    endpoint: WS_ENDPOINT.clone(),
                },
                inner: HttpsTlsRoute {
                    fragment: HttpRouteFragment {
                        host_header: "http-host".into(),
                        path_prefix: "".into(),
                        front_name: None,
                    },
                    inner: TlsRoute {
                        fragment: TlsRouteFragment {
                            root_certs: ROOT_CERTS.clone(),
                            sni: Host::Domain("sni-name".into()),
                            alpn: Some(Alpn::Http1_1),
                        },
                        inner: TcpRoute {
                            address: UnresolvedHost("target-host".into()),
                            port: TARGET_PORT,
                        },
                    },
                },
            },
            WebSocketRoute {
                fragment: WebSocketRouteFragment {
                    ws_config: WebSocketConfig::default(),
                    headers: HeaderMap::default(),
                    endpoint: WS_ENDPOINT.clone(),
                },
                inner: HttpsTlsRoute {
                    fragment: HttpRouteFragment {
                        host_header: "front-host".into(),
                        path_prefix: "/front-host-path-prefix".into(),
                        front_name: Some("front-host"),
                    },
                    inner: TlsRoute {
                        fragment: TlsRouteFragment {
                            root_certs: PROXY_ROOT_CERTS,
                            sni: Host::Domain("front-sni1".into()),
                            alpn: Some(Alpn::Http2),
                        },
                        inner: TcpRoute {
                            address: UnresolvedHost("front-sni1".into()),
                            port: http::DEFAULT_HTTPS_PORT,
                        },
                    },
                },
            },
            WebSocketRoute {
                fragment: WebSocketRouteFragment {
                    ws_config: WebSocketConfig::default(),
                    headers: HeaderMap::default(),
                    endpoint: WS_ENDPOINT.clone(),
                },
                inner: HttpsTlsRoute {
                    fragment: HttpRouteFragment {
                        host_header: "front-host".into(),
                        path_prefix: "/front-host-path-prefix".into(),
                        front_name: Some("front-host"),
                    },
                    inner: TlsRoute {
                        fragment: TlsRouteFragment {
                            root_certs: PROXY_ROOT_CERTS,
                            sni: Host::Domain("front-sni2".into()),
                            alpn: Some(Alpn::Http2),
                        },
                        inner: TcpRoute {
                            address: UnresolvedHost("front-sni2".into()),
                            port: DEFAULT_HTTPS_PORT,
                        },
                    },
                },
            },
        ];

        pretty_assertions::assert_eq!(routes, expected_routes)
    }

    #[test]
    fn tls_proxy_route() {
        const TARGET_PORT: NonZeroU16 = nonzero!(7898u16);
        const PROXY_PORT: NonZeroU16 = nonzero!(13u16);
        const PROXY_CERTS: RootCertificates = RootCertificates::FromDer(Cow::Borrowed(b"proxy"));

        let direct_provider = TlsRouteProvider {
            sni: Host::Domain("direct-sni".into()),
            certs: ROOT_CERTS.clone(),
            inner: DirectTcpRouteProvider {
                dns_hostname: "direct-target".into(),
                port: TARGET_PORT,
            },
        };

        let provider = ConnectionProxyRouteProvider {
            proxy: TlsProxy {
                proxy_host: Host::Domain("tls-proxy".into()),
                proxy_port: PROXY_PORT,
                proxy_certs: PROXY_CERTS,
            }
            .into(),
            inner: direct_provider,
        };

        let routes = provider.routes(&FakeContext::new()).collect_vec();

        assert_eq!(
            routes,
            vec![TlsRoute {
                fragment: TlsRouteFragment {
                    root_certs: ROOT_CERTS.clone(),
                    sni: Host::Domain("direct-sni".into()),
                    alpn: None,
                },
                inner: ConnectionProxyRoute::Tls {
                    proxy: TlsRoute {
                        inner: TcpRoute {
                            address: Host::Domain(UnresolvedHost("tls-proxy".into())),
                            port: PROXY_PORT,
                        },
                        fragment: TlsRouteFragment {
                            root_certs: PROXY_CERTS.clone(),
                            sni: Host::Domain("tls-proxy".into()),
                            alpn: None,
                        },
                    },
                },
            }]
        );
    }

    #[test]
    fn socks_proxy_route() {
        const TARGET_PORT: NonZeroU16 = nonzero!(7898u16);
        const PROXY_PORT: NonZeroU16 = nonzero!(13u16);
        const SOCKS_PROTOCOL: socks::Protocol = socks::Protocol::Socks5 {
            username_password: None,
        };

        let direct_provider = TlsRouteProvider {
            sni: Host::Domain("direct-sni".into()),
            certs: ROOT_CERTS.clone(),
            inner: DirectTcpRouteProvider {
                dns_hostname: "direct-target".into(),
                port: TARGET_PORT,
            },
        };

        let provider = ConnectionProxyRouteProvider {
            proxy: SocksProxy {
                proxy_host: Host::Domain("socks-proxy".into()),
                proxy_port: PROXY_PORT,
                protocol: SOCKS_PROTOCOL,
                resolve_hostname_locally: false,
            }
            .into(),
            inner: direct_provider,
        };

        let routes = provider.routes(&FakeContext::new()).collect_vec();

        let expected_routes = vec![TlsRoute {
            fragment: TlsRouteFragment {
                root_certs: ROOT_CERTS.clone(),
                sni: Host::Domain("direct-sni".into()),
                alpn: None,
            },
            inner: ConnectionProxyRoute::Socks(SocksRoute {
                proxy: TcpRoute {
                    address: Host::Domain(UnresolvedHost("socks-proxy".into())),
                    port: PROXY_PORT,
                },
                target_addr: ProxyTarget::ResolvedRemotely {
                    name: "direct-target".into(),
                },
                target_port: TARGET_PORT,
                protocol: SOCKS_PROTOCOL,
            }),
        }];
        assert_eq!(routes, expected_routes);
    }

    #[test]
    fn connection_proxy_on_top_of_websocket_route_is_provider() {
        // Compilation-only test that makes sure we can wrap a fully-specified
        // websocket route provider with a connection proxy provider.
        fn asserts_route_type<P: RouteProvider<Route = T>, T>() {}
        type MaybeProxyProvider<P> = DirectOrProxyProvider<P, ConnectionProxyRouteProvider<P>>;

        type WsProvider = WebSocketProvider<
            HttpsProvider<DomainFrontRouteProvider, TlsRouteProvider<DirectTcpRouteProvider>>,
        >;

        asserts_route_type::<
            MaybeProxyProvider<WsProvider>,
            WebSocketRoute<
                HttpsTlsRoute<
                    TlsRoute<
                        DirectOrProxyRoute<
                            TcpRoute<UnresolvedHost>,
                            ConnectionProxyRoute<Host<UnresolvedHost>>,
                        >,
                    >,
                >,
            >,
        >();
    }

    #[derive(Debug, PartialEq)]
    struct FakeConnection<R>(R);

    #[derive(Debug, PartialEq)]
    struct FakeConnectError;

    #[derive(Debug)]
    struct FakeConnector<R> {
        outgoing: mpsc::UnboundedSender<FakeConnectResponder<R>>,
    }

    #[derive(Debug)]
    struct FakeConnectResponder<R>(
        R,
        oneshot::Sender<Result<FakeConnection<R>, FakeConnectError>>,
    );

    impl<R: Debug> FakeConnectResponder<R> {
        fn route(&self) -> &R {
            &self.0
        }
        fn respond(self, result: Result<(), FakeConnectError>) {
            self.1
                .send(result.map(|()| FakeConnection(self.0)))
                .expect("not dropped")
        }
    }

    impl<R> FakeConnector<R> {
        fn new() -> (Self, impl Stream<Item = FakeConnectResponder<R>>) {
            let (outgoing, incoming) = mpsc::unbounded_channel();

            (Self { outgoing }, UnboundedReceiverStream::new(incoming))
        }
    }

    impl<R: Send> Connector<R, ()> for FakeConnector<R> {
        type Connection = FakeConnection<R>;
        type Error = FakeConnectError;

        fn connect_over(
            &self,
            (): (),
            route: R,
            _log_tag: Arc<str>,
        ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
            let (sender, receiver) = oneshot::channel();
            self.outgoing
                .send(FakeConnectResponder(route, sender))
                .unwrap();
            receiver.map(|r| r.unwrap())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn connect_slows_down_after_starting_a_connection() {
        const HOSTNAMES: &[(&str, Ipv4Addr)] = &[
            ("A", ip_addr!(v4, "1.1.1.1")),
            ("B", ip_addr!(v4, "2.2.2.2")),
            ("C", ip_addr!(v4, "3.3.3.3")),
            ("D", ip_addr!(v4, "4.4.4.4")),
            ("E", ip_addr!(v4, "5.5.5.5")),
            ("F", ip_addr!(v4, "6.6.6.6")),
            ("G", ip_addr!(v4, "7.7.7.7")),
        ];
        let (connector, mut connection_responders) = FakeConnector::new();
        let outcomes = NoDelay;
        let (resolver, mut resolution_responders) = FakeResolver::new();

        let _connection_task = tokio::spawn(async move {
            connect(
                &RouteResolver::default(),
                &outcomes,
                HOSTNAMES
                    .iter()
                    .map(|(h, _addr)| FakeRoute(UnresolvedHost::from(Arc::from(*h)))),
                &resolver,
                connector,
                (),
                "test".into(),
                |_err: FakeConnectError| ControlFlow::<Infallible>::Continue(()),
            )
            .await
        });

        // We should see all routes resolved in parallel. If we let those finish
        // immediately we should start seeing connection attempts.
        for (host, addr) in HOSTNAMES {
            let responder = resolution_responders.next().await.unwrap();
            assert_eq!(responder.hostname(), *host);
            responder.respond(Ok(LookupResult::new(
                crate::DnsSource::Test,
                vec![*addr],
                vec![],
            )));
        }

        // Let the task run so it can kick off some connection attempts.
        tokio::task::yield_now().await;

        let connections_in_progress: Vec<_> =
            std::iter::from_fn(|| connection_responders.next().now_or_never().flatten()).collect();

        assert_eq!(
            connections_in_progress
                .iter()
                .map(|responder| responder.route().0)
                .collect_vec(),
            HOSTNAMES[..1]
                .iter()
                .map(|(_, addr)| IpAddr::V4(*addr))
                .collect_vec()
        );

        // There shouldn't be any more connections in progress.
        assert_matches!(
            futures_util::poll!(connection_responders.next()),
            std::task::Poll::Pending
        );

        let start = Instant::now();
        // If, however, we wait a little longer, we will see another one!
        let next_connection = connection_responders.next().await.unwrap();
        assert_eq!(next_connection.route().0, IpAddr::V4(HOSTNAMES[1].1));
        assert_eq!(start.elapsed(), PER_CONNECTION_WAIT_DURATION);
    }

    #[tokio::test(start_paused = true)]
    async fn connect_takes_first_successful() {
        const HOSTNAMES: &[(&str, Ipv4Addr)] = &[
            ("A", ip_addr!(v4, "1.1.1.1")),
            ("B", ip_addr!(v4, "2.2.2.2")),
            ("C", ip_addr!(v4, "3.3.3.3")),
            ("D", ip_addr!(v4, "4.4.4.4")),
            ("E", ip_addr!(v4, "5.5.5.5")),
            ("F", ip_addr!(v4, "6.6.6.6")),
            ("G", ip_addr!(v4, "7.7.7.7")),
        ];

        let (connector, mut connection_responders) = FakeConnector::<FakeRoute<IpAddr>>::new();
        let outcomes = NoDelay;
        let (resolver, mut resolution_responders) = FakeResolver::new();

        const SUCCESSFUL_ROUTE_INDEX: usize = 4;

        let _connect_task = tokio::spawn(async move {
            while let Some(responder) = connection_responders.next().await {
                // Simulate the connection taking some time to succeed or fail.
                const SIMULATED_CONNECTION_DELAY: Duration = Duration::from_secs(1);

                let should_succeed =
                    responder.route().0 == IpAddr::V4(HOSTNAMES[SUCCESSFUL_ROUTE_INDEX].1);
                tokio::task::spawn(async move {
                    tokio::time::sleep(SIMULATED_CONNECTION_DELAY).await;
                    responder.respond(should_succeed.then_some(()).ok_or(FakeConnectError));
                });
            }
        });
        let _resolve_task = tokio::spawn(async move {
            // The routes should be sent for resolution in order.
            for (host, addr) in HOSTNAMES {
                let responder = resolution_responders.next().await.unwrap();
                assert_eq!(responder.hostname(), *host);
                responder.respond(Ok(LookupResult::new(
                    crate::DnsSource::Test,
                    vec![*addr],
                    vec![],
                )));
            }
        });

        let (result, updates) = connect(
            &RouteResolver::default(),
            &outcomes,
            HOSTNAMES
                .iter()
                .map(|(h, _addr)| FakeRoute(UnresolvedHost::from(Arc::from(*h)))),
            &resolver,
            connector,
            (),
            "test".into(),
            |_err: FakeConnectError| ControlFlow::<Infallible>::Continue(()),
        )
        .await;

        assert_eq!(
            result,
            Ok(FakeConnection(FakeRoute(IpAddr::V4(
                HOSTNAMES[SUCCESSFUL_ROUTE_INDEX].1
            ))))
        );

        let update_outcomes = updates
            .outcomes
            .into_iter()
            .map(|(r, a)| (r, a.result))
            .collect_vec();
        assert_eq!(
            update_outcomes,
            HOSTNAMES[..SUCCESSFUL_ROUTE_INDEX]
                .iter()
                .map(|(_, ip)| (FakeRoute(IpAddr::V4(*ip)), Err(UnsuccessfulOutcome)))
                .chain(std::iter::once({
                    let (_, ip) = HOSTNAMES[SUCCESSFUL_ROUTE_INDEX];
                    (FakeRoute(IpAddr::V4(ip)), Ok(()))
                }))
                .collect_vec()
        );
    }

    /// [`Connector`] impl whose `connect_over` never resolves.
    struct NeverConnect;

    impl<R> Connector<R, ()> for NeverConnect {
        type Connection = Infallible;

        type Error = FakeConnectError;

        fn connect_over(
            &self,
            (): (),
            _route: R,
            _log_tag: Arc<str>,
        ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
            std::future::pending()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn connect_succeeds_if_some_routes_hang_indefinitely() {
        const HOSTNAMES: &[(&str, Ipv4Addr)] = &[
            ("A", ip_addr!(v4, "1.1.1.1")),
            ("B", ip_addr!(v4, "2.2.2.2")),
            ("C", ip_addr!(v4, "3.3.3.3")),
        ];

        let (connector, connection_responders) = FakeConnector::new();

        let outcomes = NoDelay;
        let resolver = HashMap::from_iter(HOSTNAMES.iter().map(|(name, ip)| {
            (
                *name,
                LookupResult {
                    source: DnsSource::Test,
                    ipv4: vec![*ip],
                    ipv6: vec![],
                },
            )
        }));

        let connect_task = tokio::spawn(async move {
            let route_resolver = RouteResolver::default();
            super::connect(
                &route_resolver,
                outcomes,
                HOSTNAMES
                    .iter()
                    .map(|(h, _addr)| FakeRoute(UnresolvedHost::from(Arc::from(*h)))),
                &resolver,
                connector,
                (),
                "test".into(),
                |_err: FakeConnectError| ControlFlow::<Infallible>::Continue(()),
            )
            .await
        });

        // We should see routes A, B, and C tried. Don't complete any but the last one.
        let [_a, _b, c] = connection_responders
            .take(3)
            .collect::<Vec<FakeConnectResponder<_>>>()
            .await
            .try_into()
            .unwrap();
        assert_eq!(c.route(), &FakeRoute(ip_addr!("3.3.3.3")));
        c.respond(Ok(()));

        let (result, _outcomes) = connect_task.await.unwrap();

        assert_matches!(result, Ok(_));
    }

    #[tokio::test(start_paused = true)]
    async fn start_connections_sooner_if_previous_ones_finish() {
        const HOSTNAMES: &[(&str, Ipv4Addr)] = &[
            ("A", ip_addr!(v4, "1.1.1.1")),
            ("B", ip_addr!(v4, "2.2.2.2")),
            ("C", ip_addr!(v4, "3.3.3.3")),
        ];

        let (connector, mut connection_responders) = FakeConnector::new();

        let outcomes = NoDelay;
        let resolver = HashMap::from_iter(HOSTNAMES.iter().map(|(name, ip)| {
            (
                *name,
                LookupResult {
                    source: DnsSource::Test,
                    ipv4: vec![*ip],
                    ipv6: vec![],
                },
            )
        }));

        let start = Instant::now();
        let connect_task = tokio::spawn(async move {
            let route_resolver = RouteResolver::default();
            super::connect(
                &route_resolver,
                outcomes,
                HOSTNAMES
                    .iter()
                    .map(|(h, _addr)| FakeRoute(UnresolvedHost::from(Arc::from(*h)))),
                &resolver,
                connector,
                (),
                "test".into(),
                |_err: FakeConnectError| ControlFlow::<Infallible>::Continue(()),
            )
            .await
        });

        let a = connection_responders.next().await.expect("first");
        let b = connection_responders.next().await.expect("second");
        assert_eq!(
            start + PER_CONNECTION_WAIT_DURATION,
            Instant::now(),
            "should stagger connections"
        );

        let after_small_delay = start + PER_CONNECTION_WAIT_DURATION * 3 / 2;
        tokio::time::sleep_until(after_small_delay).await;
        a.respond(Err(FakeConnectError));

        let c = connection_responders.next().await.expect("second");
        assert_eq!(
            start + 2 * PER_CONNECTION_WAIT_DURATION,
            Instant::now(),
            "should not wait more than PER_CONNECTION_WAIT_DURATION start the next connection"
        );

        c.respond(Err(FakeConnectError));
        b.respond(Err(FakeConnectError));

        let (result, _outcomes) = connect_task.await.unwrap();
        assert_matches!(result, Err(_));
    }
}
