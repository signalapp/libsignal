//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;

use futures_util::TryFutureExt as _;
use nonzero_ext::nonzero;

use crate::dns::dns_utils::log_safe_domain;
use crate::errors::LogSafeDisplay;
use crate::host::Host;
use crate::route::{
    ConnectionProxyKind, ConnectionProxyRoute, Connector, DEFAULT_HTTPS_PORT, DirectOrProxyRoute,
    HttpProxyRouteFragment, HttpsProxyRoute, ProxyTarget, ResolveHostnames, ResolvedRoute,
    SocksRoute, TcpRoute, TlsRoute, TransportRoute, UnresolvedHost, UnresolvedHttpsServiceRoute,
    UnresolvedTransportRoute, UnresolvedWebsocketServiceRoute, UsesTransport,
};

/// A type that is not itself loggable but can produce a [`LogSafeDisplay`]
/// value.
///
/// The description type must be [`Display`](std::fmt::Display)-able and tagged
/// as log-safe. Implementers are encouraged to use a type that holds
/// structured data instead of a string wrapper to avoid unnecessary
/// string-ification and to enable consumers who know the concrete type access
/// to typed values.
pub trait DescribeForLog {
    /// The loggable description of `Self`.
    type Description: LogSafeDisplay;

    /// Produce a `Self::Description` for logging.
    fn describe_for_log(&self) -> Self::Description;
}

/// Wrapper for a [resolvable](ResolveHostnames) [`Route`](super) that resolves
/// to a [`WithLoggableDescription`] route.
///
/// To actually resolve a route, `R` must implement the [`DescribeForLog`]
/// trait. The description of the unresolved route is saved and added to the
/// result of [`<R as ResolveHostnames>::resolve`](ResolveHostnames::resolve).
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct ResolveWithSavedDescription<R>(pub R);

/// A [route](super) with a description for logging.
///
/// This is a wrapper for an inner route and some "description" metadata. It
/// is produced by resolving a [`ResolveWithSavedDescription<R>`] which tacks on
/// a description of the route generated before resolution.
///
/// The [`DescribedRouteConnector`], likewise, can connect routes of this type
/// by delegating to an inner [`Connector`] and pairing the description with the
/// resulting connection type on success.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct WithLoggableDescription<R, D> {
    pub route: R,
    pub description: D,
}

impl<R: UsesTransport, D> UsesTransport for WithLoggableDescription<R, D> {
    fn transport_part(&self) -> &TransportRoute {
        self.route.transport_part()
    }
    fn into_transport_part(self) -> TransportRoute {
        self.route.into_transport_part()
    }
}

/// [`Connector`] implementation for [`WithLoggableDescription`].
///
/// Implements [`Connector::connect_over`] by delegating to the wrapped
/// connector, while saving through the description (which was created from the
/// unresolved route).  If the inner connect attempt succeeds, the description
/// is paired with the connection as the output.
pub struct DescribedRouteConnector<C>(pub C);

/// Loggable description for a [`UnresolvedWebsocketServiceRoute`].
#[derive(Clone, Debug, PartialEq)]
pub struct UnresolvedRouteDescription {
    pub front: Option<&'static str>,
    pub proxy: Option<ConnectionProxyKind>,
    pub target: (Host<Arc<str>>, NonZeroU16),
}

impl<R: ResolveHostnames + DescribeForLog> ResolveHostnames for ResolveWithSavedDescription<R> {
    type Resolved = WithLoggableDescription<R::Resolved, R::Description>;

    fn hostnames(&self) -> impl Iterator<Item = &UnresolvedHost> {
        self.0.hostnames()
    }

    fn resolve(self, lookup: impl FnMut(&str) -> IpAddr) -> Self::Resolved {
        let description = self.0.describe_for_log();
        let resolved = self.0.resolve(lookup);
        WithLoggableDescription {
            route: resolved,
            description,
        }
    }
}

impl<R: ResolvedRoute, D> ResolvedRoute for WithLoggableDescription<R, D> {
    fn immediate_target(&self) -> &IpAddr {
        self.route.immediate_target()
    }
}

impl<R: Clone + Send, Inner, C: Connector<R, Inner>, D: Send>
    Connector<WithLoggableDescription<R, D>, Inner> for DescribedRouteConnector<C>
{
    type Connection = (C::Connection, D);

    type Error = C::Error;

    fn connect_over(
        &self,
        over: Inner,
        route: WithLoggableDescription<R, D>,
        log_tag: &str,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        self.0
            .connect_over(over, route.route, log_tag)
            .map_ok(|c| (c, route.description))
    }
}

impl LogSafeDisplay for UnresolvedRouteDescription {}
impl std::fmt::Display for UnresolvedRouteDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            front,
            proxy,
            target: (domain, port),
        } = self;
        write!(
            f,
            "{}:{port}",
            domain.as_deref().map_domain(log_safe_domain)
        )?;
        if let Some(front) = front {
            write!(f, " fronted by {front}")
        } else {
            f.write_str(" (direct)")
        }?;
        if let Some(proxy_kind) = proxy {
            write!(f, " through {proxy_kind:?} proxy")?
        }
        Ok(())
    }
}

impl UnresolvedRouteDescription {
    pub fn fake() -> Self {
        Self {
            front: None,
            proxy: None,
            target: (
                Host::Domain("local-test.signal.org".into()),
                nonzero!(443u16),
            ),
        }
    }
}

impl<Transport: UsesTransport<UnresolvedTransportRoute>> DescribeForLog
    for UnresolvedHttpsServiceRoute<Transport>
{
    type Description = UnresolvedRouteDescription;

    fn describe_for_log(&self) -> Self::Description {
        let Self {
            fragment: http_fragment,
            inner: transport,
        } = self;
        let TlsRoute {
            fragment: tls_fragment,
            inner: direct_or_proxy,
        } = transport.transport_part();

        let target = match direct_or_proxy {
            DirectOrProxyRoute::Direct(TcpRoute { address, port, .. }) => {
                (Host::Domain(address.clone().into()), *port)
            }
            DirectOrProxyRoute::Proxy(proxy) => match proxy {
                ConnectionProxyRoute::Tls { proxy: _ } => {
                    // The host is implicit; the proxy will look for the TLS SNI and resolve that.
                    (tls_fragment.sni.clone(), DEFAULT_HTTPS_PORT)
                }
                #[cfg(feature = "dev-util")]
                ConnectionProxyRoute::Tcp { proxy: _ } => {
                    // The host is implicit; the proxy will look for the TLS SNI and resolve that.
                    (tls_fragment.sni.clone(), DEFAULT_HTTPS_PORT)
                }
                ConnectionProxyRoute::Socks(SocksRoute {
                    target_addr,
                    target_port,
                    ..
                }) => (target_addr.as_informational_host(), *target_port),
                ConnectionProxyRoute::Https(HttpsProxyRoute {
                    fragment:
                        HttpProxyRouteFragment {
                            target_host,
                            target_port,
                            ..
                        },
                    inner: _,
                }) => (target_host.as_informational_host(), *target_port),
            },
        };

        let proxy = match &direct_or_proxy {
            DirectOrProxyRoute::Direct(_) => None,
            DirectOrProxyRoute::Proxy(proxy) => Some(ConnectionProxyKind::from(proxy)),
        };
        let front = http_fragment.front_name;

        UnresolvedRouteDescription {
            front,
            proxy,
            target,
        }
    }
}

impl<Transport: UsesTransport<UnresolvedTransportRoute>> DescribeForLog
    for UnresolvedWebsocketServiceRoute<Transport>
{
    type Description = UnresolvedRouteDescription;

    fn describe_for_log(&self) -> Self::Description {
        self.inner.describe_for_log()
    }
}

impl ProxyTarget<Host<UnresolvedHost>> {
    /// Returns a [`Host`] suitable for informational purposes.
    ///
    /// The returned type doesn't carry the locally-/remotely-resolved
    /// distinction, so use with caution!
    fn as_informational_host(&self) -> Host<Arc<str>> {
        match self {
            ProxyTarget::ResolvedLocally(host) => host.clone().map_domain(Arc::from),
            ProxyTarget::ResolvedRemotely { name } => Host::Domain(name.clone()),
        }
    }
}
