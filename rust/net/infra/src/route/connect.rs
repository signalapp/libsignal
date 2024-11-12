//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::net::IpAddr;

use derive_where::derive_where;
use futures_util::TryFutureExt;
use tokio_util::either::Either;

use crate::errors::TransportConnectError;
use crate::route::{
    ConnectionProxyRoute, DirectOrProxyRoute, HttpRouteFragment, HttpsTlsRoute, TcpRoute, TlsRoute,
    TlsRouteFragment, WebSocketRoute, WebSocketRouteFragment, WebSocketServiceRoute,
};
use crate::ws::WebSocketConnectError;

mod throttle;
pub use throttle::*;

/// Establishes a connection to a route over an inner transport.
pub trait Connector<R, Inner> {
    /// The type of connection returned on success.
    type Connection;
    /// Error output if the connection can't be established.
    type Error;

    /// Attempts to establish a connection using a route over an inner transport.
    ///
    /// Returns a [`Future`] that attempts to connect over the provided transport.
    fn connect_over(
        &self,
        over: Inner,
        route: R,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send;
}

pub trait ConnectorExt<R>: Connector<R, ()> {
    /// Convenience trait for connecting without an inner transport.
    fn connect(
        &self,
        route: R,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        self.connect_over((), route)
    }
}
impl<R, C: Connector<R, ()>> ConnectorExt<R> for C {}

/// A [`Connector`] for [`DirectOrProxyRoute`] that delegates to direct or proxy
/// connectors.
#[derive_where(Debug; D: Debug, P: Debug)]
#[derive_where(Default; D: Default, P: Default)]
pub struct DirectOrProxy<D, P, E> {
    direct: D,
    proxy: P,
    _error: PhantomData<E>,
}

/// A [`Connector`] that establishes a connection over the transport provided by
/// an inner connector.
///
/// This implements `Connector` for several different types of routes.
/// Each implementation splits off configuration for a single protocol level,
/// then uses the outer Connector to establish a connection over the transport
/// provided by the inner Connector.
#[derive_where(Debug; Outer: Debug, Inner: Debug)]
#[derive_where(Default; Outer: Default, Inner: Default)]
pub struct ComposedConnector<Outer, Inner, Error> {
    outer: Outer,
    inner: Inner,
    /// The type of error returned by [`Connector::connect_over`].
    ///
    /// This lets us produce an error type that is distinct from the inner and
    /// outer `Connector` error types.
    _error: PhantomData<Error>,
}

/// Stateless connector that connects [`WebSocketServiceRoute<IpAddr>`]s.
pub type StatelessWebSocketConnector = WebSocketHttpConnector;
/// Stateless connector that connects [`TlsTransportRoute<IpAddr>`](super::TlsTransportRoute)s.
pub type StatelessTransportConnector = TransportConnector;

type TcpConnector = crate::tcp_ssl::StatelessDirect;
type DirectProxyConnector =
    DirectOrProxy<TcpConnector, crate::tcp_ssl::proxy::StatelessProxied, TransportConnectError>;
type TransportConnector =
    ComposedConnector<crate::tcp_ssl::StatelessDirect, DirectProxyConnector, TransportConnectError>;
type WebSocketHttpConnector =
    ComposedConnector<crate::ws::Stateless, TransportConnector, WebSocketConnectError>;

const _: () = {
    const fn assert_is_connector<C: Connector<R, ()>, R>() {}

    assert_is_connector::<TcpConnector, TcpRoute<IpAddr>>();
    assert_is_connector::<
        DirectProxyConnector,
        DirectOrProxyRoute<TcpRoute<IpAddr>, ConnectionProxyRoute<IpAddr>>,
    >();
    assert_is_connector::<
        TransportConnector,
        TlsRoute<DirectOrProxyRoute<TcpRoute<IpAddr>, ConnectionProxyRoute<IpAddr>>>,
    >();
    assert_is_connector::<WebSocketHttpConnector, WebSocketServiceRoute<IpAddr>>();
};

impl<O, I, E> ComposedConnector<O, I, E> {
    pub fn new(outer: O, inner: I) -> Self {
        Self {
            outer,
            inner,
            _error: PhantomData,
        }
    }
}

/// Establishes a websocket connection over a transport stream.
///
/// This delegates to an inner connector that establishes a stream-oriented
/// connection, then to an outer one that knows how to establish a
/// websocket-over-HTTP connection on top.
///
/// See the documentation for the `Connector` impl for [`crate::ws::Stateless`]
/// for more about why [`WebSocketRouteFragment`] and [`HttpRouteFragment`] are
/// treated as a single protocol level.
impl<A, B, Inner, T, Error> Connector<WebSocketRoute<HttpsTlsRoute<T>>, Inner>
    for ComposedConnector<A, B, Error>
where
    A: Connector<(WebSocketRouteFragment, HttpRouteFragment), B::Connection> + Sync,
    B: Connector<T, Inner> + Sync,
    A::Error: Into<Error>,
    B::Error: Into<Error>,
    Inner: Send,
    T: Send,
{
    type Connection = A::Connection;

    type Error = Error;

    fn connect_over(
        &self,
        over: Inner,
        route: WebSocketRoute<HttpsTlsRoute<T>>,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let Self {
            outer,
            inner,
            _error,
        } = self;
        let WebSocketRoute {
            fragment: ws_fragment,
            inner:
                HttpsTlsRoute {
                    fragment: http_fragment,
                    inner: tls_route,
                },
        } = route;
        async move {
            let inner = inner
                .connect_over(over, tls_route)
                .await
                .map_err(Into::into)?;
            outer
                .connect_over(inner, (ws_fragment, http_fragment))
                .await
                .map_err(Into::into)
        }
    }
}

/// Establishes a TLS connection over a transport stream.
impl<A, B, Inner, T, Error> Connector<TlsRoute<T>, Inner> for ComposedConnector<A, B, Error>
where
    A: Connector<TlsRouteFragment, B::Connection> + Sync,
    B: Connector<T, Inner> + Sync,
    A::Error: Into<Error>,
    B::Error: Into<Error>,
    Inner: Send,
    T: Send,
{
    type Connection = A::Connection;

    type Error = Error;

    fn connect_over(
        &self,
        over: Inner,
        route: TlsRoute<T>,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let Self {
            outer,
            inner,
            _error,
        } = self;
        let TlsRoute {
            fragment: tls_fragment,
            inner: tcp_route,
        } = route;
        async move {
            let inner = inner
                .connect_over(over, tcp_route)
                .await
                .map_err(Into::into)?;
            outer
                .connect_over(inner, tls_fragment)
                .await
                .map_err(Into::into)
        }
    }
}

/// Establishes a connection either directly or through a proxy.
///
/// Delegates to the respective wrapped connector: [`DirectOrProxy::direct`] for
/// [`DirectOrProxyRoute::Direct`] and [`DirectOrProxy::proxy`] for
/// [`DirectOrProxyRoute::Proxy`].
impl<D, P, DR, PR, Inner, Err> Connector<DirectOrProxyRoute<DR, PR>, Inner>
    for DirectOrProxy<D, P, Err>
where
    D: Connector<DR, Inner>,
    P: Connector<PR, Inner>,
    P::Error: Into<Err>,
    D::Error: Into<Err>,
{
    type Connection = Either<D::Connection, P::Connection>;

    type Error = Err;

    fn connect_over(
        &self,
        over: Inner,
        route: DirectOrProxyRoute<DR, PR>,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        match route {
            DirectOrProxyRoute::Direct(d) => Either::Left(
                self.direct
                    .connect_over(over, d)
                    .map_ok(Either::Left)
                    .map_err(Into::into),
            ),
            DirectOrProxyRoute::Proxy(p) => Either::Right(
                self.proxy
                    .connect_over(over, p)
                    .map_ok(Either::Right)
                    .map_err(Into::into),
            ),
        }
    }
}

impl From<std::io::Error> for WebSocketConnectError {
    fn from(value: std::io::Error) -> Self {
        Self::WebSocketError(value.into())
    }
}
