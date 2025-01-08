//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::Arc;

use crate::certs::RootCertificates;
use crate::host::Host;
use crate::route::{ReplaceFragment, RouteProvider, RouteProviderContext, SimpleRoute};
use crate::Alpn;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TlsRouteFragment {
    pub root_certs: RootCertificates,
    pub sni: Host<Arc<str>>,
    pub alpn: Option<Alpn>,
}

pub type TlsRoute<T> = SimpleRoute<TlsRouteFragment, T>;

#[derive(Debug)]
pub struct TlsRouteProvider<P> {
    pub(crate) sni: Host<Arc<str>>,
    pub(crate) certs: RootCertificates,
    pub(crate) inner: P,
}

impl<T> TlsRouteProvider<T> {
    pub fn new(certs: RootCertificates, sni: Host<Arc<str>>, inner: T) -> Self {
        Self { sni, certs, inner }
    }
}

/// Sets the [`Alpn`] value for a route or route fragment.
pub(crate) trait SetAlpn {
    /// Sets the `Alpn` for `self`.
    fn set_alpn(&mut self, alpn: Alpn);
}

impl<P: RouteProvider> RouteProvider for TlsRouteProvider<P> {
    type Route = TlsRoute<P::Route>;

    fn routes<'s>(
        &'s self,
        context: &impl RouteProviderContext,
    ) -> impl Iterator<Item = Self::Route> + 's {
        let Self { sni, certs, inner } = self;

        inner.routes(context).map(|route| TlsRoute {
            fragment: TlsRouteFragment {
                root_certs: certs.clone(),
                sni: sni.clone(),
                alpn: None,
            },
            inner: route,
        })
    }
}

impl<R: ReplaceFragment<S>, S> ReplaceFragment<S> for TlsRoute<R> {
    type Replacement<T> = TlsRoute<R::Replacement<T>>;

    fn replace<T>(self, make_fragment: impl FnOnce(S) -> T) -> Self::Replacement<T> {
        let Self { fragment, inner } = self;
        TlsRoute {
            inner: inner.replace(make_fragment),
            fragment,
        }
    }
}

impl<T> SetAlpn for TlsRoute<T> {
    fn set_alpn(&mut self, alpn: Alpn) {
        self.fragment.set_alpn(alpn)
    }
}

impl SetAlpn for TlsRouteFragment {
    fn set_alpn(&mut self, alpn: Alpn) {
        self.alpn = Some(alpn);
    }
}

impl<T, H> From<&TlsRoute<T>> for Host<H>
where
    for<'a> &'a T: Into<Host<H>>,
{
    fn from(value: &TlsRoute<T>) -> Self {
        (&value.inner).into()
    }
}
