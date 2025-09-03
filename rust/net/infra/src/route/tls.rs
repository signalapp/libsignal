//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::Arc;

use boring_signal::ssl::SslVersion;

use crate::Alpn;
use crate::certs::RootCertificates;
use crate::host::Host;
use crate::route::{ReplaceFragment, RouteProvider, RouteProviderContext, SimpleRoute};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsRouteFragment {
    pub root_certs: RootCertificates,
    pub sni: Host<Arc<str>>,
    pub alpn: Option<Alpn>,
    pub min_protocol_version: Option<SslVersion>,
}

impl std::hash::Hash for TlsRouteFragment {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.root_certs.hash(state);
        self.sni.hash(state);
        self.alpn.hash(state);
        // Ignore SslVersion, an opaque enum. Unfortunate, but a valid hash implementation.
    }
}

pub type TlsRoute<T> = SimpleRoute<TlsRouteFragment, T>;

#[derive(Debug)]
pub struct TlsRouteProvider<P> {
    pub(crate) sni: Host<Arc<str>>,
    pub(crate) certs: RootCertificates,
    pub(crate) min_protocol_version: Option<SslVersion>,
    pub(crate) inner: P,
}

impl<T> TlsRouteProvider<T> {
    pub fn new(
        certs: RootCertificates,
        min_protocol_version: Option<SslVersion>,
        sni: Host<Arc<str>>,
        inner: T,
    ) -> Self {
        Self {
            sni,
            certs,
            min_protocol_version,
            inner,
        }
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
        let Self {
            sni,
            certs,
            min_protocol_version,
            inner,
        } = self;

        inner.routes(context).map(|route| TlsRoute {
            fragment: TlsRouteFragment {
                root_certs: certs.clone(),
                sni: sni.clone(),
                alpn: None,
                min_protocol_version: *min_protocol_version,
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
