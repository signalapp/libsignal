//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU16;
use std::sync::Arc;

use either::Either;

use crate::certs::RootCertificates;
use crate::host::Host;
use crate::route::{
    ReplaceFragment, RouteProvider, TcpRoute, TlsRoute, TlsRouteFragment, UnresolvedHost,
};
use crate::tcp_ssl::proxy::socks;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SocksRoute<Addr> {
    pub proxy: TcpRoute<Addr>,
    pub target_addr: SocksTarget<Addr>,
    pub target_port: NonZeroU16,
    pub protocol: socks::Protocol,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ConnectionProxyRoute<Addr> {
    Tls {
        proxy: TlsRoute<TcpRoute<Addr>>,
    },
    /// TCP proxy without encryption, only for testing.
    Tcp {
        proxy: TcpRoute<Addr>,
    },
    Socks(SocksRoute<Addr>),
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum SocksTarget<Addr> {
    ResolvedLocally(Addr),
    ResolvedRemotely { name: Arc<str> },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DirectOrProxyRoute<D, P> {
    Direct(D),
    Proxy(P),
}

#[derive(Clone, Debug, PartialEq)]
pub enum DirectOrProxyProvider<D, P> {
    Direct(D),
    Proxy(P),
}

#[derive(Debug)]
pub enum ConnectionProxyConfig {
    TlsProxy {
        proxy_host: Host<Arc<str>>,
        proxy_port: NonZeroU16,
        proxy_certs: RootCertificates,
    },
    TcpProxy {
        proxy_host: Host<Arc<str>>,
        proxy_port: NonZeroU16,
    },
    Socks {
        proxy_host: Host<Arc<str>>,
        proxy_port: NonZeroU16,
        protocol: socks::Protocol,
        resolve_hostname_locally: bool,
    },
}

pub struct ConnectionProxyRouteProvider<P> {
    pub(crate) proxy: ConnectionProxyConfig,
    pub(crate) inner: P,
}

impl<P> ConnectionProxyRouteProvider<P> {
    pub fn new(proxy: ConnectionProxyConfig, inner: P) -> Self {
        Self { proxy, inner }
    }
}

type DirectOrProxyReplacement =
    DirectOrProxyRoute<TcpRoute<UnresolvedHost>, ConnectionProxyRoute<Host<UnresolvedHost>>>;

impl<D, P, R> RouteProvider for DirectOrProxyProvider<D, P>
where
    D: RouteProvider,
    P: RouteProvider,
    D::Route: ReplaceFragment<TcpRoute<UnresolvedHost>, Replacement<DirectOrProxyReplacement> = R>,
    P::Route: ReplaceFragment<
        ConnectionProxyRoute<Host<UnresolvedHost>>,
        Replacement<DirectOrProxyReplacement> = R,
    >,
{
    type Route = R;

    fn routes(&self) -> impl Iterator<Item = Self::Route> + '_ {
        match self {
            Self::Direct(direct) => Either::Left(
                direct
                    .routes()
                    .map(|route: D::Route| route.replace(DirectOrProxyRoute::Direct)),
            ),
            Self::Proxy(proxy) => Either::Right(proxy.routes().map(|route: P::Route| {
                route.replace(|cpr: ConnectionProxyRoute<Host<UnresolvedHost>>| {
                    DirectOrProxyRoute::Proxy(cpr)
                })
            })),
        }
    }
}

impl<P> RouteProvider for ConnectionProxyRouteProvider<P>
where
    P: RouteProvider,
    P::Route: ReplaceFragment<TcpRoute<UnresolvedHost>>,
{
    type Route = <P::Route as ReplaceFragment<TcpRoute<UnresolvedHost>>>::Replacement<
        ConnectionProxyRoute<Host<UnresolvedHost>>,
    >;

    fn routes(&self) -> impl Iterator<Item = Self::Route> + '_ {
        let Self { proxy, inner } = self;

        match proxy {
            ConnectionProxyConfig::TlsProxy {
                proxy_host,
                proxy_port,
                proxy_certs,
            } => {
                let tls_fragment = TlsRouteFragment {
                    root_certs: proxy_certs.clone(),
                    sni: proxy_host.clone(),
                    alpn: None,
                };

                let tcp = TcpRoute {
                    address: match proxy_host {
                        Host::Ip(ip) => Host::Ip(*ip),
                        Host::Domain(domain) => Host::Domain(UnresolvedHost(Arc::clone(domain))),
                    },
                    port: *proxy_port,
                };

                let tls_route = TlsRoute {
                    inner: tcp,
                    fragment: tls_fragment,
                };
                let routes = inner.routes().map(move |route| {
                    route.replace(|_: TcpRoute<UnresolvedHost>| ConnectionProxyRoute::Tls {
                        proxy: tls_route.clone(),
                    })
                });
                Either::Left(routes)
            }

            ConnectionProxyConfig::Socks {
                proxy_host,
                proxy_port,
                protocol,
                resolve_hostname_locally,
            } => {
                let proxy = TcpRoute {
                    address: match proxy_host {
                        Host::Ip(ip_addr) => Host::Ip(*ip_addr),
                        Host::Domain(domain) => Host::Domain(UnresolvedHost(Arc::clone(domain))),
                    },
                    port: *proxy_port,
                };
                let routes = inner.routes().map(move |route| {
                    route.replace(|TcpRoute { address, port }| {
                        ConnectionProxyRoute::Socks(SocksRoute {
                            proxy: proxy.clone(),
                            protocol: protocol.clone(),
                            target_addr: if *resolve_hostname_locally {
                                SocksTarget::ResolvedLocally(Host::Domain(address))
                            } else {
                                SocksTarget::ResolvedRemotely { name: address.0 }
                            },
                            target_port: port,
                        })
                    })
                });
                Either::Right(Either::Left(routes))
            }

            ConnectionProxyConfig::TcpProxy {
                proxy_host,
                proxy_port,
            } => {
                let tcp = TcpRoute {
                    address: match proxy_host {
                        Host::Ip(ip) => Host::Ip(*ip),
                        Host::Domain(domain) => Host::Domain(UnresolvedHost(Arc::clone(domain))),
                    },
                    port: *proxy_port,
                };

                let routes = inner.routes().map(move |route| {
                    route.replace(|_: TcpRoute<UnresolvedHost>| ConnectionProxyRoute::Tcp {
                        proxy: tcp.clone(),
                    })
                });
                Either::Right(Either::Right(routes))
            }
        }
    }
}

impl<R> ReplaceFragment<ConnectionProxyRoute<R>> for ConnectionProxyRoute<R> {
    type Replacement<T> = T;

    fn replace<T>(
        self,
        make_fragment: impl FnOnce(ConnectionProxyRoute<R>) -> T,
    ) -> Self::Replacement<T> {
        make_fragment(self)
    }
}
