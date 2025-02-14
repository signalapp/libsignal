//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;
use std::net::IpAddr;
use std::num::NonZeroU16;
use std::sync::Arc;

use libsignal_net_infra::host::Host;
use libsignal_net_infra::route::{
    ConnectionProxyRoute, DirectOrProxyRoute, HttpProxyRouteFragment, HttpsProxyRoute, ProxyTarget,
    SocksRoute, TcpRoute, TransportRoute, DEFAULT_HTTPS_PORT,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum FakeTransportTarget {
    TcpThroughProxy {
        host: Host<Arc<str>>,
        port: NonZeroU16,
    },
    Tcp {
        host: IpAddr,
        port: NonZeroU16,
    },
    Tls {
        sni: Host<Arc<str>>,
    },
}

impl FakeTransportTarget {
    pub(crate) fn from_route(route: &TransportRoute) -> [Self; 2] {
        let TransportRoute { inner, fragment } = route;
        let tcp_target = match inner {
            DirectOrProxyRoute::Direct(tcp) => tcp.clone().into(),
            DirectOrProxyRoute::Proxy(proxy) => match proxy {
                ConnectionProxyRoute::Tls { .. } | ConnectionProxyRoute::Tcp { .. } => {
                    Self::TcpThroughProxy {
                        host: fragment.sni.clone(),
                        port: DEFAULT_HTTPS_PORT,
                    }
                }
                ConnectionProxyRoute::Socks(SocksRoute {
                    target_addr: target_host,
                    target_port,
                    ..
                })
                | ConnectionProxyRoute::Https(HttpsProxyRoute {
                    fragment:
                        HttpProxyRouteFragment {
                            target_host,
                            target_port,
                            ..
                        },
                    ..
                }) => Self::TcpThroughProxy {
                    host: match target_host {
                        ProxyTarget::ResolvedLocally(ip) => (*ip).into(),
                        ProxyTarget::ResolvedRemotely { name } => Host::Domain(name.clone()),
                    },
                    port: *target_port,
                },
            },
        };

        [
            tcp_target,
            FakeTransportTarget::Tls {
                sni: fragment.sni.clone(),
            },
        ]
    }
}

impl Display for FakeTransportTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FakeTransportTarget::TcpThroughProxy { host, port } => {
                write!(f, "proxy to {host}:{port}")
            }
            FakeTransportTarget::Tcp { host, port } => write!(f, "{host}:{port}"),
            FakeTransportTarget::Tls { sni } => write!(f, "TLS @ {sni}"),
        }
    }
}

impl From<TcpRoute<IpAddr>> for FakeTransportTarget {
    fn from(TcpRoute { address, port }: TcpRoute<IpAddr>) -> Self {
        Self::Tcp {
            host: address,
            port,
        }
    }
}
