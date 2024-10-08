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
use futures_util::{FutureExt as _, TryStreamExt};
use itertools::Itertools;

use crate::dns::lookup_result::LookupResult;
use crate::dns::{DnsError, DnsResolver};
use crate::host::Host;
use crate::route::{
    ConnectionProxyRoute, DirectOrProxyRoute, HttpsTlsRoute, SocksTarget, TcpRoute, TlsRoute,
    UnresolvedHost, WebSocketRoute,
};

/// A route with hostnames that can be resolved.
pub trait ResolveHostnames {
    /// The new route type with no unresolved hostnames.
    type Resolved;

    /// Enumerates all the unresolved hostnames in `self`.
    fn hostnames(&self) -> impl Iterator<Item = &UnresolvedHost>;

    /// Produces a new route by resolving the unresolved hostnames in self.
    ///
    /// The provided `lookup` callback must be able to resolve every hostname
    /// that is yielded by `self.hostnames()`.
    fn resolve(self, lookup: impl FnMut(&str) -> IpAddr) -> Self::Resolved;
}

pub trait Resolver {
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

/// Resolves all unresolved hostnames in the given route.
///
/// Asynchronously resolves all routes and produces the resolved routes. Since
/// DNS resolution for a given host can produce multiple addresses, the output
/// is a sequence of routes.
pub async fn resolve_route<R: ResolveHostnames + Clone + 'static>(
    dns: &impl Resolver,
    route: R,
) -> Result<impl Iterator<Item = R::Resolved> + Debug, DnsError> {
    let to_resolve = route.hostnames().map(|UnresolvedHost(hostname)| {
        dns.lookup_ip(hostname)
            .map(|result| result.map(|lookup| (Arc::clone(hostname), lookup)))
    });

    let futures = FuturesUnordered::from_iter(to_resolve);

    let resolved: Vec<_> = futures.try_collect().await?;

    // Squash each of the resolved (host, lookup result) pairs into an iterator
    // over (host, IP addr). This gives us an iterator of iterators.
    let host_ip_candidates = resolved.into_iter().map(|(hostname, lookup_result)| {
        lookup_result
            .into_iter()
            .map(move |ip| (Arc::clone(&hostname), ip))
    });

    // Produce the set of all possible resolutions of each of the host names to
    // IP addresses.
    let all_resolutions = host_ip_candidates.multi_cartesian_product();

    // Produce a new resolution of the input route for each of the possible
    // resolutions of the hostnames that it contained.
    let resolved_routes = all_resolutions.map(move |host_to_ip| {
        let lookup_hostname = |hostname: &str| {
            // This is a linear search through a list but it should be small; no
            // route contains more than a few hostnames.
            host_to_ip
                .iter()
                .find_map(|(h, ip)| (**h == *hostname).then_some(*ip))
                .expect("earlier lookup was successful")
        };
        route.clone().resolve(lookup_hostname)
    });

    Ok(resolved_routes)
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

impl<A: ResolveHostnames> ResolveHostnames for SocksTarget<A> {
    type Resolved = SocksTarget<A::Resolved>;

    fn hostnames(&self) -> impl Iterator<Item = &UnresolvedHost> {
        match self {
            SocksTarget::ResolvedLocally(a) => Either::Left(a.hostnames()),
            SocksTarget::ResolvedRemotely { name: _ } => Either::Right(std::iter::empty()),
        }
    }

    fn resolve(self, lookup: impl FnMut(&str) -> IpAddr) -> Self::Resolved {
        match self {
            SocksTarget::ResolvedLocally(a) => SocksTarget::ResolvedLocally(a.resolve(lookup)),
            SocksTarget::ResolvedRemotely { name } => SocksTarget::ResolvedRemotely { name },
        }
    }
}

impl<A: ResolveHostnames> ResolveHostnames for ConnectionProxyRoute<A> {
    type Resolved = ConnectionProxyRoute<A::Resolved>;

    fn hostnames(&self) -> impl Iterator<Item = &UnresolvedHost> {
        match self {
            Self::Tls { proxy } => Either::Left(proxy.hostnames()),
            Self::Socks {
                proxy,
                target_addr,
                target_port: _,
                protocol: _,
            } => Either::Right(proxy.hostnames().chain(target_addr.hostnames())),
        }
    }

    fn resolve(self, mut lookup: impl FnMut(&str) -> IpAddr) -> Self::Resolved {
        match self {
            ConnectionProxyRoute::Tls { proxy } => ConnectionProxyRoute::Tls {
                proxy: proxy.resolve(lookup),
            },
            ConnectionProxyRoute::Socks {
                proxy,
                target_addr,
                target_port,
                protocol,
            } => ConnectionProxyRoute::Socks {
                proxy: proxy.resolve(&mut lookup),
                target_addr: target_addr.resolve(lookup),
                target_port,
                protocol,
            },
        }
    }
}

#[cfg(test)]
mod test {
    use std::collections::{HashMap, HashSet};
    use std::num::NonZeroU16;

    use assert_matches::assert_matches;
    use const_str::ip_addr;
    use futures_util::{pin_mut, FutureExt as _, Stream, StreamExt as _};
    use nonzero_ext::nonzero;
    use tokio::sync::{mpsc, oneshot};
    use tokio_stream::wrappers::UnboundedReceiverStream;

    use super::*;
    use crate::certs::RootCertificates;
    use crate::host::Host;
    use crate::route::{
        DirectOrProxyRoute, HttpRouteFragment, HttpsServiceRoute, TlsRouteFragment,
    };
    use crate::tcp_ssl::proxy::socks;
    use crate::DnsSource;

    const PROXY_PORT: NonZeroU16 = nonzero!(444u16);
    const TARGET_PORT: NonZeroU16 = nonzero!(888u16);

    /// Implementation of [`Resolver`] that gets results from
    /// [`FakeResponder`]s.
    struct FakeResolver {
        request_tx: mpsc::UnboundedSender<FakeResponder>,
    }

    struct FakeResponder {
        hostname: String,
        result_sender: oneshot::Sender<Result<LookupResult, DnsError>>,
    }

    impl FakeResolver {
        fn new() -> (FakeResolver, impl Stream<Item = FakeResponder> + Unpin) {
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
        fn hostname(&self) -> &str {
            &self.hostname
        }
        fn respond(self, result: Result<LookupResult, DnsError>) {
            let _ignore_error = self.result_sender.send(result);
        }
    }

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

        assert_matches!(resolve.await, Err(DnsError::NoData));
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
            HashSet::<Vec<_>>::from_iter(result),
            HashSet::from_iter([
                vec![ip_addr!("::1111"), ip_addr!("::3333"), ip_addr!("::2222")],
                vec![ip_addr!("::1111"), ip_addr!("::3333"), ip_addr!("5.5.5.5")]
            ])
        );
    }

    impl Resolver for HashMap<&'static str, LookupResult> {
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
        };

        let tls_fragment = TlsRouteFragment {
            root_certs: RootCertificates::Native,
            sni: None,
            alpn: None,
        };

        fn socks_route<A>(proxy: A, target: A) -> ConnectionProxyRoute<A> {
            ConnectionProxyRoute::Socks {
                proxy: TcpRoute {
                    address: proxy,
                    port: PROXY_PORT,
                },
                target_addr: SocksTarget::ResolvedLocally(target),
                target_port: TARGET_PORT,
                protocol: socks::Protocol::Socks5 {
                    username_password: None,
                },
            }
        }

        let unresolved_route: HttpsServiceRoute<_> = HttpsTlsRoute {
            inner: TlsRoute {
                inner: DirectOrProxyRoute::Proxy(socks_route(
                    Host::Domain(UnresolvedHost("proxy-domain".into())),
                    Host::Domain(UnresolvedHost("target-domain".into())),
                )),
                fragment: tls_fragment.clone(),
            },
            fragment: http_fragment.clone(),
        };

        let resolved = HashSet::from_iter(
            resolve_route(&dns, unresolved_route)
                .now_or_never()
                .expect("all resolution is static")
                .expect("all hostnames are resolvable"),
        );

        let expected_routes = HashSet::from([
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
        ]);

        pretty_assertions::assert_eq!(resolved, expected_routes);
    }
}
