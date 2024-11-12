//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;

use crate::host::Host;
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

impl<D> From<&TcpRoute<IpAddr>> for Host<D> {
    fn from(value: &TcpRoute<IpAddr>) -> Self {
        Host::Ip(value.address)
    }
}

pub struct DirectTcpRouteProvider {
    pub(crate) dns_hostname: Arc<str>,
    pub(crate) port: NonZeroU16,
}

impl DirectTcpRouteProvider {
    pub fn new(hostname: Arc<str>, port: NonZeroU16) -> Self {
        Self {
            dns_hostname: hostname,
            port,
        }
    }
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
