//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::future::Future;
use std::net::IpAddr;
use std::sync::Arc;

use either::Either;
use futures_util::stream::FuturesUnordered;
use futures_util::{FutureExt as _, TryStreamExt as _};
use itertools::Itertools;

use crate::dns::lookup_result::LookupResult;
use crate::dns::{DnsError, DnsResolver};
use crate::host::Host;
use crate::route::{
    ConnectionProxyRoute, DirectOrProxyRoute, HttpProxyRouteFragment, HttpsProxyRoute,
    HttpsTlsRoute, ProxyTarget, SocksRoute, TcpRoute, TlsRoute, UnresolvedHost, WebSocketRoute,
};

/// A route with hostnames that can be resolved.
///
/// This should be implemented for routes that contain [`UnresolvedHost`] values
/// (including in nested types). Most implementations will be almost completely
/// straightforward delegations to inner types. At the bottom is
/// `UnresolvedHost`, which implements this trait.
pub trait ResolveHostnames {
    /// The new route type with no unresolved hostnames.
    type Resolved: ResolvedRoute;

    /// Enumerates all the unresolved hostnames in `self`.
    fn hostnames(&self) -> impl Iterator<Item = &UnresolvedHost>;

    /// Produces a new route by resolving the unresolved hostnames in self.
    ///
    /// The provided `lookup` callback must be able to resolve every hostname
    /// that is yielded by `self.hostnames()`.
    fn resolve(self, lookup: impl FnMut(&str) -> IpAddr) -> Self::Resolved;
}

/// A route that has had all its hostnames resolved to IP addresses.
pub trait ResolvedRoute {
    /// The IP address of the host that this route connects directly to.
    ///
    /// For a route that communicates through a proxy, this will be the address
    /// of the proxy. Otherwise it will be the IP address of the target.
    fn immediate_target(&self) -> &IpAddr;
}

/// Asynchronous resolver for individual names.
///
/// This exists mostly as an abstraction over [`DnsResolver`] for the purposes
/// of mocking during tests.
pub trait Resolver {
    /// Asynchronously looks up a single domain name.
    ///
    /// Returns a [`Future`] that resolves to the result of the lookup.
    fn lookup_ip(
        &self,
        hostname: &str,
    ) -> impl Future<Output = Result<LookupResult, DnsError>> + Send;
}

impl Resolver for DnsResolver {
    fn lookup_ip(&self, hostname: &str) -> impl Future<Output = Result<LookupResult, DnsError>> {
        DnsResolver::lookup_ip(self, hostname)
    }
}

/// The output of [`resolve_route`] on successful resolution.
///
/// The actual type isn't important, but writing it out lets the compiler infer
/// that the type implements [`Debug`] when `R` does.
type ResolveRouteIter<R> = std::iter::Chain<
    itertools::Interleave<std::vec::IntoIter<R>, std::vec::IntoIter<R>>,
    std::vec::IntoIter<R>,
>;

/// Resolves all unresolved hostnames in the given route.
///
/// Asynchronously resolves all routes and produces the resolved routes. Since
/// DNS resolution for a given host can produce multiple addresses, the output
/// is a sequence of routes in the order in which connections should be
/// attempted.
pub async fn resolve_route<R: ResolveHostnames + Clone + 'static>(
    dns: &impl Resolver,
    route: R,
) -> Result<ResolveRouteIter<R::Resolved>, (Arc<str>, DnsError)> {
    let to_resolve = route.hostnames().map(|UnresolvedHost(hostname)| {
        dns.lookup_ip(hostname).map(|result| match result {
            Ok(lookup) => Ok((Arc::clone(hostname), lookup)),
            Err(e) => Err((Arc::clone(hostname), e)),
        })
    });

    let resolved = FuturesUnordered::from_iter(to_resolve)
        .try_collect::<Vec<_>>()
        .await?;

    let resolutions = resolved
        .into_iter()
        .map(|(hostname, result)| std::iter::repeat(hostname).zip(result))
        .multi_cartesian_product();

    // Produce a new resolution of the input route for each of the possible
    // resolutions of the hostnames that it contained.
    let [mut v4_routes, mut v6_routes, mut other_routes] = [(); 3].map(|_| Vec::new());
    for host_to_ip in resolutions {
        let mut route_ip_version = RouteIpVersion::None;
        let lookup_hostname = |hostname: &str| {
            // This is a linear search through a list but it should be small; no
            // route contains more than a few hostnames.
            let addr = host_to_ip
                .iter()
                .find_map(|(h, ip)| (**h == *hostname).then_some(*ip))
                .expect("earlier lookup was successful");

            route_ip_version.update_from(&addr);
            addr
        };
        let resolved = route.clone().resolve(lookup_hostname);
        let destination = match route_ip_version {
            RouteIpVersion::V4 => &mut v4_routes,
            RouteIpVersion::V6 => &mut v6_routes,
            RouteIpVersion::None | RouteIpVersion::Mixed => &mut other_routes,
        };
        destination.push(resolved);
    }

    let resolved_routes = itertools::interleave(v6_routes, v4_routes).chain(other_routes);
    Ok(resolved_routes)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum RouteIpVersion {
    None,
    V4,
    V6,
    Mixed,
}

impl RouteIpVersion {
    fn update_from(&mut self, addr: &IpAddr) {
        *self = match (*self, addr) {
            (RouteIpVersion::V4, IpAddr::V6(_)) | (RouteIpVersion::V6, IpAddr::V4(_)) => {
                RouteIpVersion::Mixed
            }
            (RouteIpVersion::None, IpAddr::V4(_)) => RouteIpVersion::V4,
            (RouteIpVersion::None, IpAddr::V6(_)) => RouteIpVersion::V6,
            (v @ RouteIpVersion::V4, IpAddr::V4(_))
            | (v @ RouteIpVersion::V6, IpAddr::V6(_))
            | (v @ RouteIpVersion::Mixed, _) => v,
        }
    }
}

impl ResolveHostnames for UnresolvedHost {
    type Resolved = IpAddr;

    fn hostnames(&self) -> impl Iterator<Item = &UnresolvedHost> {
        std::iter::once(self)
    }

    fn resolve(self, mut lookup: impl FnMut(&str) -> IpAddr) -> Self::Resolved {
        lookup(&self.0)
    }
}

impl<A: ResolveHostnames<Resolved = IpAddr>> ResolveHostnames for Host<A> {
    type Resolved = IpAddr;

    fn hostnames(&self) -> impl Iterator<Item = &UnresolvedHost> {
        match self {
            Self::Domain(d) => Either::Left(d.hostnames()),
            Self::Ip(_) => Either::Right(std::iter::empty()),
        }
    }

    fn resolve(self, lookup: impl FnMut(&str) -> IpAddr) -> Self::Resolved {
        match self {
            Host::Ip(ip) => ip,
            Host::Domain(domain) => domain.resolve(lookup),
        }
    }
}

macro_rules! impl_resolve_hostnames {
    ($typ:ident, $delegate_field:ident, $($other_fields:tt)*) => {
        impl <A: ResolveHostnames> ResolveHostnames for $typ<A> {
            type Resolved = $typ<A::Resolved>;

            fn hostnames(&self) -> impl Iterator<Item = &UnresolvedHost> {
                self.$delegate_field.hostnames()
            }

            fn resolve(self, lookup: impl FnMut(&str) -> IpAddr) -> Self::Resolved {
                let Self { $delegate_field, $($other_fields)* } = self;
                Self::Resolved {
                    $delegate_field: $delegate_field.resolve(lookup),
                    $($other_fields)*
                }
            }
        }
    };
    ($typ:ident, $delegate_field:ident) => {
        impl_resolve_hostnames!($typ, $delegate_field,);
    }
}

impl_resolve_hostnames!(TcpRoute, address, port);
impl_resolve_hostnames!(TlsRoute, inner, fragment);
impl_resolve_hostnames!(HttpsTlsRoute, inner, fragment);
impl_resolve_hostnames!(WebSocketRoute, inner, fragment);

impl<D: ResolveHostnames, P: ResolveHostnames> ResolveHostnames for DirectOrProxyRoute<D, P> {
    type Resolved = DirectOrProxyRoute<D::Resolved, P::Resolved>;

    fn hostnames(&self) -> impl Iterator<Item = &UnresolvedHost> {
        match self {
            DirectOrProxyRoute::Direct(d) => Either::Left(d.hostnames()),
            DirectOrProxyRoute::Proxy(p) => Either::Right(p.hostnames()),
        }
    }

    fn resolve(self, lookup: impl FnMut(&str) -> IpAddr) -> Self::Resolved {
        match self {
            DirectOrProxyRoute::Direct(d) => DirectOrProxyRoute::Direct(d.resolve(lookup)),
            DirectOrProxyRoute::Proxy(p) => DirectOrProxyRoute::Proxy(p.resolve(lookup)),
        }
    }
}

impl<A: ResolveHostnames> ResolveHostnames for ConnectionProxyRoute<A> {
    type Resolved = ConnectionProxyRoute<A::Resolved>;

    fn hostnames(&self) -> impl Iterator<Item = &UnresolvedHost> {
        match self {
            Self::Tls { proxy } => Either::Left(Either::Left(proxy.hostnames())),
            Self::Tcp { proxy } => Either::Left(Either::Right(proxy.hostnames())),
            Self::Socks(socks) => Either::Right(Either::Right(socks.hostnames())),
            Self::Https(http) => Either::Right(Either::Left(http.hostnames())),
        }
    }

    fn resolve(self, lookup: impl FnMut(&str) -> IpAddr) -> Self::Resolved {
        match self {
            ConnectionProxyRoute::Tls { proxy } => ConnectionProxyRoute::Tls {
                proxy: proxy.resolve(lookup),
            },
            ConnectionProxyRoute::Tcp { proxy } => ConnectionProxyRoute::Tcp {
                proxy: proxy.resolve(lookup),
            },
            ConnectionProxyRoute::Socks(socks) => {
                ConnectionProxyRoute::Socks(socks.resolve(lookup))
            }
            ConnectionProxyRoute::Https(http) => ConnectionProxyRoute::Https(http.resolve(lookup)),
        }
    }
}

impl<A: ResolveHostnames> ResolveHostnames for HttpsProxyRoute<A> {
    type Resolved = HttpsProxyRoute<A::Resolved>;

    fn hostnames(&self) -> impl Iterator<Item = &UnresolvedHost> {
        let Self {
            inner,
            fragment:
                HttpProxyRouteFragment {
                    target_host,
                    target_port: _,
                    authorization: _,
                },
        } = self;
        inner
            .as_ref()
            .map_either(ResolveHostnames::hostnames, ResolveHostnames::hostnames)
            .chain(target_host.locally_resolved_hostnames())
    }
    fn resolve(self, mut lookup: impl FnMut(&str) -> IpAddr) -> Self::Resolved {
        let Self {
            inner,
            fragment:
                HttpProxyRouteFragment {
                    target_host,
                    target_port,
                    authorization,
                },
        } = self;
        let fragment = HttpProxyRouteFragment {
            target_host: target_host.replace_locally_resolved(&mut lookup),
            target_port,
            authorization,
        };
        Self::Resolved {
            inner: inner.map_either_with(
                lookup,
                |lookup, r| r.resolve(lookup),
                |lookup, r| r.resolve(lookup),
            ),
            fragment,
        }
    }
}

impl<A: ResolveHostnames> ResolveHostnames for SocksRoute<A> {
    type Resolved = SocksRoute<A::Resolved>;

    fn hostnames(&self) -> impl Iterator<Item = &UnresolvedHost> {
        let Self {
            proxy,
            target_addr,
            target_port: _,
            protocol: _,
        } = self;
        proxy
            .hostnames()
            .chain(target_addr.locally_resolved_hostnames())
    }

    fn resolve(self, mut lookup: impl FnMut(&str) -> IpAddr) -> Self::Resolved {
        let Self {
            proxy,
            target_addr,
            target_port,
            protocol,
        } = self;
        let target_addr = target_addr.replace_locally_resolved(&mut lookup);
        SocksRoute {
            proxy: proxy.resolve(lookup),
            target_addr,
            target_port,
            protocol,
        }
    }
}

impl<A: ResolveHostnames> ProxyTarget<A> {
    fn locally_resolved_hostnames(&self) -> impl Iterator<Item = &UnresolvedHost> {
        match self {
            ProxyTarget::ResolvedLocally(addr) => Some(addr.hostnames()),
            ProxyTarget::ResolvedRemotely { name: _ } => None,
        }
        .into_iter()
        .flatten()
    }

    fn replace_locally_resolved(
        self,
        lookup: impl FnMut(&str) -> IpAddr,
    ) -> ProxyTarget<A::Resolved> {
        match self {
            ProxyTarget::ResolvedLocally(addr) => {
                ProxyTarget::ResolvedLocally(addr.resolve(lookup))
            }
            ProxyTarget::ResolvedRemotely { name } => ProxyTarget::ResolvedRemotely { name },
        }
    }
}

macro_rules! impl_resolved_route {
    ($typ:ident, $delegate_field:ident) => {
        impl<A: ResolvedRoute> ResolvedRoute for $typ<A> {
            fn immediate_target(&self) -> &IpAddr {
                self.$delegate_field.immediate_target()
            }
        }
    };
}

impl ResolvedRoute for IpAddr {
    fn immediate_target(&self) -> &IpAddr {
        self
    }
}

impl_resolved_route!(TcpRoute, address);
impl_resolved_route!(TlsRoute, inner);
impl_resolved_route!(HttpsTlsRoute, inner);
impl_resolved_route!(HttpsProxyRoute, inner);
impl_resolved_route!(WebSocketRoute, inner);

impl<D: ResolvedRoute, P: ResolvedRoute> ResolvedRoute for DirectOrProxyRoute<D, P> {
    fn immediate_target(&self) -> &IpAddr {
        match self {
            DirectOrProxyRoute::Direct(d) => d.immediate_target(),
            DirectOrProxyRoute::Proxy(p) => p.immediate_target(),
        }
    }
}

impl<A: ResolvedRoute> ResolvedRoute for ConnectionProxyRoute<A> {
    fn immediate_target(&self) -> &IpAddr {
        match self {
            ConnectionProxyRoute::Tls { proxy } => proxy.immediate_target(),
            ConnectionProxyRoute::Tcp { proxy } => proxy.immediate_target(),
            ConnectionProxyRoute::Socks(proxy) => proxy.immediate_target(),
            ConnectionProxyRoute::Https(proxy) => proxy.immediate_target(),
        }
    }
}

impl<A: ResolvedRoute> ResolvedRoute for SocksRoute<A> {
    fn immediate_target(&self) -> &IpAddr {
        let Self {
            proxy,
            target_addr: _,
            target_port: _,
            protocol: _,
        } = self;
        proxy.immediate_target()
    }
}

impl<L: ResolvedRoute, R: ResolvedRoute> ResolvedRoute for Either<L, R> {
    fn immediate_target(&self) -> &IpAddr {
        self.as_ref()
            .map_either(
                ResolvedRoute::immediate_target,
                ResolvedRoute::immediate_target,
            )
            .into_inner()
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod testutils {
    use futures_util::Stream;
    use tokio::sync::{mpsc, oneshot};
    use tokio_stream::wrappers::UnboundedReceiverStream;

    use super::*;

    /// Implementation of [`Resolver`] that gets results from
    /// [`FakeResponder`]s.
    pub struct FakeResolver {
        request_tx: mpsc::UnboundedSender<FakeResponder>,
    }

    #[derive(Debug)]
    pub struct FakeResponder {
        hostname: String,
        result_sender: oneshot::Sender<Result<LookupResult, DnsError>>,
    }

    impl FakeResolver {
        pub fn new() -> (FakeResolver, impl Stream<Item = FakeResponder> + Unpin) {
            let (request_tx, request_rx) = mpsc::unbounded_channel();
            (
                FakeResolver { request_tx },
                UnboundedReceiverStream::new(request_rx),
            )
        }
    }

    impl Resolver for FakeResolver {
        fn lookup_ip(
            &self,
            hostname: &str,
        ) -> impl Future<Output = Result<LookupResult, DnsError>> {
            let (response_tx, response_rx) = oneshot::channel();

            let tx = self.request_tx.clone();
            async move {
                tx.send(FakeResponder {
                    hostname: hostname.to_owned(),
                    result_sender: response_tx,
                })
                .map_err(|_| DnsError::TransportFailure)?;
                response_rx.await.unwrap_or(Err(DnsError::NoData))
            }
        }
    }

    impl FakeResponder {
        pub fn hostname(&self) -> &str {
            &self.hostname
        }
        pub fn respond(self, result: Result<LookupResult, DnsError>) {
            let _ignore_error = self.result_sender.send(result);
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::{HashMap, HashSet};
    use std::num::NonZeroU16;

    use assert_matches::assert_matches;
    use const_str::ip_addr;
    use futures_util::{pin_mut, FutureExt as _, StreamExt as _};
    use nonzero_ext::nonzero;

    use super::*;
    use crate::certs::RootCertificates;
    use crate::host::Host;
    use crate::route::resolve::testutils::{FakeResolver, FakeResponder};
    use crate::route::{
        DirectOrProxyRoute, HttpRouteFragment, SocksRoute, TlsRouteFragment,
        UnresolvedHttpsServiceRoute,
    };
    use crate::tcp_ssl::proxy::socks;
    use crate::DnsSource;

    const PROXY_PORT: NonZeroU16 = nonzero!(444u16);
    const TARGET_PORT: NonZeroU16 = nonzero!(888u16);

    /// Let us use a `Vec` for testing [`resolve_route`] instead of a real route
    /// type that would require us to specify a bunch of unnecessary extra
    /// information.
    impl<R: ResolveHostnames> ResolveHostnames for Vec<R> {
        type Resolved = Vec<R::Resolved>;

        fn hostnames(&self) -> impl Iterator<Item = &UnresolvedHost> {
            self.iter().flat_map(ResolveHostnames::hostnames)
        }

        fn resolve(self, mut lookup: impl FnMut(&str) -> IpAddr) -> Self::Resolved {
            self.into_iter().map(|r| r.resolve(&mut lookup)).collect()
        }
    }

    impl<A: ResolvedRoute> ResolvedRoute for Vec<A> {
        fn immediate_target(&self) -> &IpAddr {
            self.first().unwrap().immediate_target()
        }
    }

    #[tokio::test]
    async fn returns_error_on_resolution_failure() {
        let (resolver, mut responders) = FakeResolver::new();

        let unresolved_route = vec![UnresolvedHost("hostname".into())];

        let resolve = resolve_route(&resolver, unresolved_route);
        pin_mut!(resolve);

        // Kick off the name resolutions.
        assert_matches!(
            futures_util::poll!(resolve.as_mut()),
            std::task::Poll::Pending
        );
        let responder = responders.next().await.expect("incoming request");

        assert_eq!(responder.hostname(), "hostname");
        responder.respond(Err(DnsError::NoData));

        assert_matches!(resolve.await, Err((_, DnsError::NoData)));
    }

    #[tokio::test]
    async fn runs_resolutions_in_parallel() {
        let (resolver, mut responders) = FakeResolver::new();

        let unresolved_route = vec![
            UnresolvedHost("host-1".into()),
            UnresolvedHost("host-2".into()),
            UnresolvedHost("host-3".into()),
        ];

        let resolve = resolve_route(&resolver, unresolved_route);
        pin_mut!(resolve);

        let recv_responders = async {
            [
                responders.next().await,
                responders.next().await,
                responders.next().await,
            ]
            .map(|r| r.expect("multiple requests"))
        };

        let responders = tokio::select! {
            _ = resolve.as_mut() => unreachable!("resolution isn't done yet"),
            responders = recv_responders => responders
        };

        let mut responders = HashMap::<String, FakeResponder>::from_iter(
            responders
                .into_iter()
                .map(|r| (r.hostname().to_string(), r)),
        );

        assert_eq!(
            HashSet::from_iter(responders.keys().map(|k| &**k)),
            HashSet::from(["host-1", "host-2", "host-3"])
        );

        // If one of the resolutions is still pending, the whole thing can't
        // finish.
        responders
            .remove("host-1")
            .unwrap()
            .respond(Ok(LookupResult {
                source: DnsSource::Cache,
                ipv4: vec![],
                ipv6: vec![ip_addr!(v6, "::1111")],
            }));
        responders
            .remove("host-3")
            .unwrap()
            .respond(Ok(LookupResult {
                source: DnsSource::Cache,
                ipv4: vec![ip_addr!(v4, "5.5.5.5")],
                ipv6: vec![ip_addr!(v6, "::2222")],
            }));

        let () = tokio::select! {
            biased;
            _ = resolve.as_mut() => unreachable!("second lookup isn't done yet"),
            () = std::future::ready(()) => ()
        };

        responders
            .remove("host-2")
            .unwrap()
            .respond(Ok(LookupResult {
                source: DnsSource::Test,
                ipv4: vec![],
                ipv6: vec![ip_addr!(v6, "::3333")],
            }));
        let result = resolve.await.expect("finished");

        pretty_assertions::assert_eq!(
            result.collect_vec(),
            [
                vec![ip_addr!("::1111"), ip_addr!("::3333"), ip_addr!("::2222")],
                vec![ip_addr!("::1111"), ip_addr!("::3333"), ip_addr!("5.5.5.5")]
            ],
        );
    }

    impl Resolver for HashMap<&str, LookupResult> {
        fn lookup_ip(
            &self,
            hostname: &str,
        ) -> impl Future<Output = Result<LookupResult, DnsError>> {
            std::future::ready(self.get(hostname).ok_or(DnsError::LookupFailed).cloned())
        }
    }

    #[test]
    fn resolve_hostnames_in_real_route() {
        let dns = HashMap::from([
            (
                "proxy-domain",
                LookupResult {
                    source: DnsSource::Static,
                    ipv4: vec![ip_addr!(v4, "10.10.10.10")],
                    ipv6: vec![ip_addr!(v6, "::ffff")],
                },
            ),
            (
                "target-domain",
                LookupResult {
                    source: DnsSource::Static,
                    ipv4: vec![ip_addr!(v4, "1.2.3.4"), ip_addr!(v4, "1.2.3.5")],
                    ipv6: vec![ip_addr!(v6, "::1234")],
                },
            ),
        ]);

        let http_fragment = HttpRouteFragment {
            host_header: "target-domain".into(),
            path_prefix: "".into(),
            front_name: None,
        };

        let tls_fragment = TlsRouteFragment {
            root_certs: RootCertificates::Native,
            sni: Host::Domain("target-domain".into()),
            alpn: None,
        };

        fn socks_route<A>(proxy: A, target: A) -> ConnectionProxyRoute<A> {
            ConnectionProxyRoute::Socks(SocksRoute {
                proxy: TcpRoute {
                    address: proxy,
                    port: PROXY_PORT,
                },
                target_addr: ProxyTarget::ResolvedLocally(target),
                target_port: TARGET_PORT,
                protocol: socks::Protocol::Socks5 {
                    username_password: None,
                },
            })
        }

        let unresolved_route: UnresolvedHttpsServiceRoute = HttpsTlsRoute {
            inner: TlsRoute {
                inner: DirectOrProxyRoute::Proxy(socks_route(
                    Host::Domain(UnresolvedHost("proxy-domain".into())),
                    Host::Domain(UnresolvedHost("target-domain".into())),
                )),
                fragment: tls_fragment.clone(),
            },
            fragment: http_fragment.clone(),
        };

        let resolved = resolve_route(&dns, unresolved_route)
            .now_or_never()
            .expect("all resolution is static")
            .expect("all hostnames are resolvable")
            .collect_vec();

        let expected_routes = [
            // IPv6 only
            HttpsTlsRoute {
                inner: TlsRoute {
                    inner: DirectOrProxyRoute::Proxy(socks_route(
                        ip_addr!("::ffff"),
                        ip_addr!("::1234"),
                    )),
                    fragment: tls_fragment.clone(),
                },
                fragment: http_fragment.clone(),
            },
            // IPv4 only
            HttpsTlsRoute {
                inner: TlsRoute {
                    inner: DirectOrProxyRoute::Proxy(socks_route(
                        ip_addr!("10.10.10.10"),
                        ip_addr!("1.2.3.4"),
                    )),
                    fragment: tls_fragment.clone(),
                },
                fragment: http_fragment.clone(),
            },
            HttpsTlsRoute {
                inner: TlsRoute {
                    inner: DirectOrProxyRoute::Proxy(socks_route(
                        ip_addr!("10.10.10.10"),
                        ip_addr!("1.2.3.5"),
                    )),
                    fragment: tls_fragment.clone(),
                },
                fragment: http_fragment.clone(),
            },
            // Mixed
            HttpsTlsRoute {
                inner: TlsRoute {
                    inner: DirectOrProxyRoute::Proxy(socks_route(
                        ip_addr!("::ffff"),
                        ip_addr!("1.2.3.4"),
                    )),
                    fragment: tls_fragment.clone(),
                },
                fragment: http_fragment.clone(),
            },
            HttpsTlsRoute {
                inner: TlsRoute {
                    inner: DirectOrProxyRoute::Proxy(socks_route(
                        ip_addr!("::ffff"),
                        ip_addr!("1.2.3.5"),
                    )),
                    fragment: tls_fragment.clone(),
                },
                fragment: http_fragment.clone(),
            },
            HttpsTlsRoute {
                inner: TlsRoute {
                    inner: DirectOrProxyRoute::Proxy(socks_route(
                        ip_addr!("10.10.10.10"),
                        ip_addr!("::1234"),
                    )),
                    fragment: tls_fragment.clone(),
                },
                fragment: http_fragment.clone(),
            },
        ];

        pretty_assertions::assert_eq!(resolved, expected_routes);
    }
}
