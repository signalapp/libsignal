//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU16;
use std::sync::Arc;

use nonzero_ext::nonzero;

use crate::certs::RootCertificates;
use crate::route::{
    ReplaceFragment, RouteProvider, SetAlpn, SimpleRoute, TcpRoute, TlsRoute, TlsRouteFragment,
    UnresolvedHost,
};
use crate::Alpn;

pub const DEFAULT_HTTPS_PORT: NonZeroU16 = nonzero!(443u16);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HttpRouteFragment {
    pub host_header: Arc<str>,
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
pub(crate) struct DomainFrontConfig {
    /// The value of the HTTP Host header
    pub(crate) http_host: Arc<str>,
    /// Domain names to use for DNS resolution and TLS SNI.
    pub(crate) sni_list: Vec<Arc<str>>,
}

impl RouteProvider for DomainFrontRouteProvider {
    type Route = HttpsTlsRoute<TlsRoute<TcpRoute<UnresolvedHost>>>;

    fn routes(&self) -> impl Iterator<Item = Self::Route> + '_ {
        let Self {
            fronts,
            http_version,
        } = self;

        fronts.iter().flat_map(
            |DomainFrontConfig {
                 http_host,
                 sni_list,
             }| {
                sni_list.iter().map(|sni| HttpsTlsRoute {
                    inner: TlsRoute {
                        inner: TcpRoute {
                            address: UnresolvedHost(Arc::clone(sni)),
                            port: DEFAULT_HTTPS_PORT,
                        },
                        fragment: TlsRouteFragment {
                            root_certs: RootCertificates::Native,
                            sni: Some(Arc::clone(sni)),
                            alpn: Some((*http_version).into()),
                        },
                    },
                    fragment: HttpRouteFragment {
                        host_header: Arc::clone(http_host),
                    },
                })
            },
        )
    }
}

impl<F, P> RouteProvider for HttpsProvider<F, P>
where
    P: RouteProvider,
    F: RouteProvider<Route = HttpsTlsRoute<P::Route>>,
    P::Route: SetAlpn,
{
    type Route = HttpsTlsRoute<P::Route>;
    fn routes(&self) -> impl Iterator<Item = Self::Route> + '_ {
        let Self {
            direct_host_header,
            direct_http_version,
            domain_front,
            inner,
        } = self;

        inner
            .routes()
            .map(|mut inner| {
                inner.set_alpn(Alpn::from(*direct_http_version));

                HttpsTlsRoute {
                    fragment: HttpRouteFragment {
                        host_header: Arc::clone(direct_host_header),
                    },
                    inner,
                }
            })
            .chain(domain_front.routes())
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
