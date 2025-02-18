//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU16;
use std::sync::Arc;

use nonzero_ext::nonzero;

use crate::certs::RootCertificates;
use crate::host::Host;
use crate::route::{
    ReplaceFragment, RouteProvider, RouteProviderContext, SetAlpn, SimpleRoute, TcpRoute, TlsRoute,
    TlsRouteFragment, UnresolvedHost,
};
use crate::Alpn;

pub const DEFAULT_HTTPS_PORT: NonZeroU16 = nonzero!(443u16);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HttpRouteFragment {
    pub host_header: Arc<str>,
    pub path_prefix: Arc<str>,
    /// Only for logging; the name of the domain front for this proxy.
    pub front_name: Option<&'static str>,
}

pub type HttpsTlsRoute<T> = SimpleRoute<HttpRouteFragment, T>;

#[derive(Debug)]
pub struct HttpsProvider<F, P> {
    pub(crate) direct_host_header: Arc<str>,
    pub(crate) direct_http_version: HttpVersion,
    pub(crate) domain_front: F,
    pub(crate) inner: P,
}

#[derive(Debug)]
pub struct DomainFrontRouteProvider {
    pub(crate) fronts: Vec<DomainFrontConfig>,
    pub(crate) http_version: HttpVersion,
}

/// A supported HTTP version for [`HttpsTlsRoute`].
///
/// This is distinct from [`http::Version`] since only a subset of versions are
/// supported, and is distinct from [`Alpn`] which is TLS-specific and could in
/// theory represent non-HTTP-version values.
#[derive(Copy, Clone, Debug)]
pub enum HttpVersion {
    Http1_1,
    Http2,
}

#[derive(Clone, Debug)]
pub struct DomainFrontConfig {
    /// The value of the HTTP Host header
    pub http_host: Arc<str>,
    /// Domain names to use for DNS resolution and TLS SNI.
    pub sni_list: Vec<Arc<str>>,
    /// The certs to use for establishing a TLS connection.
    pub root_certs: RootCertificates,
    /// A string to prepend to the path of outgoing HTTP requests.
    pub path_prefix: Arc<str>,
    /// A loggable name for the front.
    pub front_name: &'static str,
    /// Whether to use all SNIs or just one.
    pub return_routes_with_all_snis: bool,
}

impl<F, P> HttpsProvider<F, P> {
    pub fn new(
        direct_host: Arc<str>,
        direct_version: HttpVersion,
        domain_front: F,
        inner: P,
    ) -> Self {
        Self {
            direct_host_header: direct_host,
            direct_http_version: direct_version,
            domain_front,
            inner,
        }
    }
}

impl DomainFrontRouteProvider {
    pub fn new(http_version: HttpVersion, fronts: Vec<DomainFrontConfig>) -> Self {
        Self {
            fronts,
            http_version,
        }
    }
}

impl RouteProvider for DomainFrontRouteProvider {
    type Route = HttpsTlsRoute<TlsRoute<TcpRoute<UnresolvedHost>>>;

    fn routes<'s>(
        &'s self,
        context: &impl RouteProviderContext,
    ) -> impl Iterator<Item = Self::Route> + 's {
        let Self {
            fronts,
            http_version,
        } = self;

        let sni_index = context.random_usize();

        fronts.iter().flat_map(
            move |DomainFrontConfig {
                      http_host,
                      sni_list,
                      root_certs,
                      path_prefix,
                      front_name,
                      return_routes_with_all_snis,
                  }| {
                let sni_list = if *return_routes_with_all_snis {
                    &**sni_list
                } else if !sni_list.is_empty() {
                    let index = sni_index % sni_list.len();
                    &sni_list[index..][..1]
                } else {
                    &[]
                };
                sni_list.iter().map(|sni| HttpsTlsRoute {
                    inner: TlsRoute {
                        inner: TcpRoute {
                            address: UnresolvedHost(Arc::clone(sni)),
                            port: DEFAULT_HTTPS_PORT,
                        },
                        fragment: TlsRouteFragment {
                            root_certs: root_certs.clone(),
                            sni: Host::Domain(Arc::clone(sni)),
                            alpn: Some((*http_version).into()),
                        },
                    },
                    fragment: HttpRouteFragment {
                        host_header: Arc::clone(http_host),
                        path_prefix: Arc::clone(path_prefix),
                        front_name: Some(*front_name),
                    },
                })
            },
        )
    }
}

impl<F, P> RouteProvider for HttpsProvider<F, P>
where
    P: RouteProvider<Route: SetAlpn>,
    F: RouteProvider<Route = HttpsTlsRoute<P::Route>>,
{
    type Route = HttpsTlsRoute<P::Route>;
    fn routes<'s>(
        &'s self,
        context: &impl RouteProviderContext,
    ) -> impl Iterator<Item = Self::Route> + 's {
        let Self {
            direct_host_header,
            direct_http_version,
            domain_front,
            inner,
        } = self;

        inner
            .routes(context)
            .map(|mut inner| {
                inner.set_alpn(Alpn::from(*direct_http_version));

                HttpsTlsRoute {
                    fragment: HttpRouteFragment {
                        host_header: Arc::clone(direct_host_header),
                        path_prefix: "".into(),
                        front_name: None,
                    },
                    inner,
                }
            })
            .chain(domain_front.routes(context))
    }
}

impl<R: ReplaceFragment<S>, S> ReplaceFragment<S> for HttpsTlsRoute<R> {
    type Replacement<T> = HttpsTlsRoute<R::Replacement<T>>;

    fn replace<T>(self, make_fragment: impl FnOnce(S) -> T) -> Self::Replacement<T> {
        let Self { inner, fragment } = self;
        HttpsTlsRoute {
            inner: inner.replace(make_fragment),
            fragment,
        }
    }
}

impl From<HttpVersion> for Alpn {
    fn from(value: HttpVersion) -> Self {
        match value {
            HttpVersion::Http1_1 => Alpn::Http1_1,
            HttpVersion::Http2 => Alpn::Http2,
        }
    }
}

#[cfg(test)]
mod test {
    use itertools::Itertools;

    use super::*;
    use crate::route::testutils::FakeContext;
    use crate::route::{DirectTcpRouteProvider, TlsRouteProvider};

    #[derive(Copy, Clone, Debug, Default)]
    struct FakeProvider;

    impl RouteProvider for FakeProvider {
        type Route = ();

        fn routes<'s>(
            &'s self,
            _context: &impl RouteProviderContext,
        ) -> impl Iterator<Item = Self::Route> + 's {
            std::iter::once(())
        }
    }

    #[test]
    fn http_provider_route_order() {
        const DIRECT_TCP_PORT: NonZeroU16 = nonzero!(1234u16);
        let provider = HttpsProvider {
            direct_host_header: "direct-host".into(),
            direct_http_version: HttpVersion::Http2,
            domain_front: DomainFrontRouteProvider {
                fronts: vec![
                    DomainFrontConfig {
                        http_host: "front-host-1".into(),
                        sni_list: vec!["front-sni-1a".into(), "front-sni-1b".into()],
                        root_certs: RootCertificates::Native,
                        path_prefix: "/prefix-1".into(),
                        front_name: "front-1",
                        return_routes_with_all_snis: true,
                    },
                    DomainFrontConfig {
                        http_host: "front-host-2".into(),
                        sni_list: vec!["front-sni-2a".into(), "front-sni-2b".into()],
                        root_certs: RootCertificates::Native,
                        path_prefix: "/prefix-2".into(),
                        front_name: "front-2",
                        return_routes_with_all_snis: false,
                    },
                ],
                http_version: HttpVersion::Http1_1,
            },
            inner: TlsRouteProvider {
                sni: Host::Domain("direct-host".into()),
                certs: RootCertificates::Native,
                inner: DirectTcpRouteProvider {
                    dns_hostname: "direct-tcp-host".into(),
                    port: DIRECT_TCP_PORT,
                },
            },
        };

        let routes = provider.routes(&FakeContext::new()).collect_vec();

        assert_eq!(
            routes,
            [
                HttpsTlsRoute {
                    fragment: HttpRouteFragment {
                        host_header: "direct-host".into(),
                        path_prefix: "".into(),
                        front_name: None,
                    },
                    inner: TlsRoute {
                        fragment: TlsRouteFragment {
                            root_certs: RootCertificates::Native,
                            sni: Host::Domain("direct-host".into()),
                            alpn: Some(Alpn::Http2)
                        },
                        inner: TcpRoute {
                            address: UnresolvedHost("direct-tcp-host".into()),
                            port: DIRECT_TCP_PORT,
                        },
                    },
                },
                HttpsTlsRoute {
                    fragment: HttpRouteFragment {
                        host_header: "front-host-1".into(),
                        path_prefix: "/prefix-1".into(),
                        front_name: Some("front-1")
                    },
                    inner: TlsRoute {
                        fragment: TlsRouteFragment {
                            root_certs: RootCertificates::Native,
                            sni: Host::Domain("front-sni-1a".into()),
                            alpn: Some(Alpn::Http1_1)
                        },
                        inner: TcpRoute {
                            address: UnresolvedHost("front-sni-1a".into()),
                            port: DEFAULT_HTTPS_PORT
                        },
                    }
                },
                HttpsTlsRoute {
                    fragment: HttpRouteFragment {
                        host_header: "front-host-1".into(),
                        path_prefix: "/prefix-1".into(),
                        front_name: Some("front-1")
                    },
                    inner: TlsRoute {
                        fragment: TlsRouteFragment {
                            root_certs: RootCertificates::Native,
                            sni: Host::Domain("front-sni-1b".into()),
                            alpn: Some(Alpn::Http1_1)
                        },
                        inner: TcpRoute {
                            address: UnresolvedHost("front-sni-1b".into()),
                            port: DEFAULT_HTTPS_PORT
                        },
                    }
                },
                HttpsTlsRoute {
                    fragment: HttpRouteFragment {
                        host_header: "front-host-2".into(),
                        path_prefix: "/prefix-2".into(),
                        front_name: Some("front-2")
                    },
                    inner: TlsRoute {
                        fragment: TlsRouteFragment {
                            root_certs: RootCertificates::Native,
                            sni: Host::Domain("front-sni-2b".into()),
                            alpn: Some(Alpn::Http1_1)
                        },
                        inner: TcpRoute {
                            address: UnresolvedHost("front-sni-2b".into()),
                            port: DEFAULT_HTTPS_PORT
                        },
                    }
                }
            ]
        );
    }
}
