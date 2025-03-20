//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;

use static_assertions::assert_impl_all;

use crate::errors::TransportConnectError;
use crate::route::{
    ConnectionProxyRoute, DirectOrProxyRoute, HttpRouteFragment, HttpsTlsRoute, TcpRoute, TlsRoute,
    TlsRouteFragment, TransportRoute, WebSocketRoute, WebSocketRouteFragment,
    WebSocketServiceRoute,
};
use crate::ws::WebSocketConnectError;

mod composed;
pub use composed::*;

mod direct_or_proxy;
pub use direct_or_proxy::*;

mod interface_monitor;
pub use interface_monitor::*;

mod preconnect;
pub use preconnect::*;

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
        log_tag: Arc<str>,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send;
}

pub trait ConnectorExt<R>: Connector<R, ()> {
    /// Convenience trait for connecting without an inner transport.
    fn connect(
        &self,
        route: R,
        log_tag: Arc<str>,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        self.connect_over((), route, log_tag)
    }
}
impl<R, C: Connector<R, ()>> ConnectorExt<R> for C {}

/// Allows state to be shared across Connectors.
pub trait ConnectorFactory<R> {
    /// The connector produced by this factory.
    type Connector: Connector<R, (), Connection = Self::Connection>;
    /// The type of connection returned by the connector.
    ///
    /// Technically redundant, but useful for constraints.
    type Connection;

    /// Creates a new connector to use for a particular connection attempt.
    fn make(&self) -> Self::Connector;
}

/// Stateless connector that connects [`WebSocketServiceRoute`]s.
pub type StatelessWebSocketConnector = WebSocketHttpConnector;
/// Stateless connector that connects [`TransportRoute`]s.
pub type StatelessTransportConnector = TransportConnector;

type TcpConnector = crate::tcp_ssl::StatelessDirect;
type DirectProxyConnector =
    DirectOrProxy<TcpConnector, crate::tcp_ssl::proxy::StatelessProxied, TransportConnectError>;
type TransportConnector =
    ComposedConnector<crate::tcp_ssl::StatelessDirect, DirectProxyConnector, TransportConnectError>;
type WebSocketHttpConnector =
    ComposedConnector<crate::ws::Stateless, TransportConnector, WebSocketConnectError>;

assert_impl_all!(TcpConnector: Connector<TcpRoute<IpAddr>, ()>);
assert_impl_all!(
    DirectProxyConnector:
    Connector<DirectOrProxyRoute<TcpRoute<IpAddr>, ConnectionProxyRoute<IpAddr>>, ()>
);
assert_impl_all!(TransportConnector: Connector<TransportRoute, ()>);
assert_impl_all!(WebSocketHttpConnector: Connector<WebSocketServiceRoute, ()>);

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
    A: Connector<(WebSocketRouteFragment, HttpRouteFragment), B::Connection, Error: Into<Error>>
        + Sync,
    B: Connector<T, Inner, Error: Into<Error>> + Sync,
    Inner: Send,
    T: Send,
{
    type Connection = A::Connection;

    type Error = Error;

    fn connect_over(
        &self,
        over: Inner,
        route: WebSocketRoute<HttpsTlsRoute<T>>,
        log_tag: Arc<str>,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let WebSocketRoute {
            fragment: ws_fragment,
            inner:
                HttpsTlsRoute {
                    fragment: http_fragment,
                    inner: tls_route,
                },
        } = route;

        self.connect_inner_then_outer(over, tls_route, (ws_fragment, http_fragment), log_tag)
    }
}

/// Establishes a TLS connection over a transport stream.
impl<A, B, Inner, T, Error> Connector<TlsRoute<T>, Inner> for ComposedConnector<A, B, Error>
where
    A: Connector<TlsRouteFragment, B::Connection, Error: Into<Error>> + Sync,
    B: Connector<T, Inner, Error: Into<Error>> + Sync,
    Inner: Send,
    T: Send,
{
    type Connection = A::Connection;

    type Error = Error;

    fn connect_over(
        &self,
        over: Inner,
        route: TlsRoute<T>,
        log_tag: Arc<str>,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let TlsRoute {
            fragment: tls_fragment,
            inner: tcp_route,
        } = route;
        self.connect_inner_then_outer(over, tcp_route, tls_fragment, log_tag)
    }
}

impl<C: Connector<R, Inner>, R, Inner> Connector<R, Inner> for &C {
    type Connection = C::Connection;

    type Error = C::Error;

    fn connect_over(
        &self,
        over: Inner,
        route: R,
        log_tag: Arc<str>,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        (*self).connect_over(over, route, log_tag)
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod testutils {
    use super::*;

    /// [`Connector`] impl that wraps a [`Fn`].
    ///
    /// Using unnamed functions as Connector impls isn't great for readability,
    /// so only allow it in test code.
    #[derive(Clone)]
    pub struct ConnectFn<F>(pub F);

    impl<R, Inner, Fut, F, C, E> Connector<R, Inner> for ConnectFn<F>
    where
        F: Fn(Inner, R, Arc<str>) -> Fut,
        Fut: Future<Output = Result<C, E>> + Send,
    {
        type Connection = C;

        type Error = E;

        fn connect_over(
            &self,
            over: Inner,
            route: R,
            log_tag: Arc<str>,
        ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
            self.0(over, route, log_tag)
        }
    }

    impl<R, F> ConnectorFactory<R> for ConnectFn<F>
    where
        ConnectFn<F>: Connector<R, ()> + Clone,
    {
        type Connector = Self;
        type Connection = <Self as Connector<R, ()>>::Connection;

        fn make(&self) -> Self::Connector {
            self.clone()
        }
    }
}
