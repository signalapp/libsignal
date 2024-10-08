//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU16;
use std::sync::Arc;

use crate::route::{ReplaceFragment, RouteProvider, UnresolvedHost};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TcpRoute<Addr> {
    pub address: Addr,
    pub port: NonZeroU16,
}

impl<A> ReplaceFragment<Self> for TcpRoute<A> {
    type Replacement<T> = T;

    fn replace<T>(self, make_fragment: impl FnOnce(Self) -> T) -> Self::Replacement<T> {
        make_fragment(self)
    }
}

pub struct DirectTcpRouteProvider {
    pub(crate) dns_hostname: Arc<str>,
    pub(crate) port: NonZeroU16,
}

impl RouteProvider for DirectTcpRouteProvider {
    type Route = TcpRoute<UnresolvedHost>;

    fn routes(&self) -> impl Iterator<Item = Self::Route> + '_ {
        let Self { dns_hostname, port } = self;

        std::iter::once(TcpRoute {
            address: UnresolvedHost(Arc::clone(dns_hostname)),
            port: *port,
        })
    }
}
