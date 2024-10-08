//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::Arc;

mod http;
pub use http::*;

mod proxy;
pub use proxy::*;

mod resolve;
pub use resolve::*;

mod tcp;
pub use tcp::*;

mod tls;
pub use tls::*;

mod ws;
pub use ws::*;

use crate::host::Host;

/// Produces routes to a destination.
///
/// A "route" here is a path to a target destination of some kind. It does not
/// have to be fully-specified but it does contain information about how to
/// reach a remote target.
pub trait RouteProvider {
    /// The type of route being produced.
    type Route;

    /// Produces an iterator over routes.
    ///
    /// The iterator is allowed to borrow from `self` as an optimization.
    fn routes(&self) -> impl Iterator<Item = Self::Route> + '_;
}

/// A hostname in a route that can later be resolved to IP addresses.
#[derive(Clone, Debug, PartialEq)]
pub struct UnresolvedHost(Arc<str>);

/// Allows replacing part of a route.
///
/// The value being replaced has type `F` and the replacement type is determined
/// by the caller.
pub trait ReplaceFragment<F> {
    /// The type of the new value after replacing `F` with a value of type `T`.
    type Replacement<T>;

    /// Replace a value of type `F` in `Self` with a value of type `T`.
    ///
    /// The callback constructs a value of type `T` given the former `F` value.
    fn replace<T>(self, make_fragment: impl FnOnce(F) -> T) -> Self::Replacement<T>;
}

/// Generic route type that stacks a protocol-specific fragment on top of an
/// inner route.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct SimpleRoute<Fragment, Inner> {
    /// The protocol-specific information for this route.
    pub fragment: Fragment,
    /// The lower-level route value.
    pub inner: Inner,
}

pub type HttpsServiceRoute<Addr> =
    HttpsTlsRoute<TlsRoute<DirectOrProxyRoute<TcpRoute<Addr>, ConnectionProxyRoute<Host<Addr>>>>>;
pub type WebSocketServiceRoute<Addr> = WebSocketRoute<HttpsServiceRoute<Addr>>;

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::num::NonZeroU16;

    use ::http::uri::PathAndQuery;
    use itertools::Itertools as _;
    use nonzero_ext::nonzero;
    use tungstenite::protocol::WebSocketConfig;

    use super::*;
    use crate::certs::RootCertificates;
    use crate::host::Host;
    use crate::tcp_ssl::proxy::socks;
    use crate::Alpn;

    lazy_static::lazy_static! {
        static ref WS_ENDPOINT: PathAndQuery =  PathAndQuery::from_static("/ws-path");
    }
    const ROOT_CERTS: RootCertificates = RootCertificates::FromDer(Cow::Borrowed(b"cert"));

    #[test]
    fn websocket_routes() {
        const TARGET_PORT: NonZeroU16 = nonzero!(8765u16);

        let provider = WebSocketProvider {
            fragment: WebSocketRouteFragment {
                ws_config: WebSocketConfig::default(),
                endpoint: WS_ENDPOINT.clone(),
            },
            inner: HttpsProvider {
                direct_host_header: "http-host".into(),
                direct_http_version: HttpVersion::Http1_1,
                domain_front: DomainFrontRouteProvider {
                    fronts: vec![DomainFrontConfig {
                        http_host: "front-host".into(),
                        sni_list: vec!["front-sni1".into(), "front-sni2".into()],
                    }],
                    http_version: HttpVersion::Http2,
                },
                inner: TlsRouteProvider {
                    sni: Some("sni-name".into()),
                    certs: ROOT_CERTS.clone(),
                    inner: DirectTcpRouteProvider {
                        dns_hostname: "target-host".into(),
                        port: TARGET_PORT,
                    },
                },
            },
        };

        let routes = RouteProvider::routes(&provider).collect_vec();

        let expected_routes = vec![
            WebSocketRoute {
                fragment: WebSocketRouteFragment {
                    ws_config: WebSocketConfig::default(),
                    endpoint: WS_ENDPOINT.clone(),
                },
                inner: HttpsTlsRoute {
                    fragment: HttpRouteFragment {
                        host_header: "http-host".into(),
                    },
                    inner: TlsRoute {
                        fragment: TlsRouteFragment {
                            root_certs: ROOT_CERTS.clone(),
                            sni: Some("sni-name".into()),
                            alpn: Some(Alpn::Http1_1),
                        },
                        inner: TcpRoute {
                            address: UnresolvedHost("target-host".into()),
                            port: TARGET_PORT,
                        },
                    },
                },
            },
            WebSocketRoute {
                fragment: WebSocketRouteFragment {
                    ws_config: WebSocketConfig::default(),
                    endpoint: WS_ENDPOINT.clone(),
                },
                inner: HttpsTlsRoute {
                    fragment: HttpRouteFragment {
                        host_header: "front-host".into(),
                    },
                    inner: TlsRoute {
                        fragment: TlsRouteFragment {
                            root_certs: RootCertificates::Native,
                            sni: Some("front-sni1".into()),
                            alpn: Some(Alpn::Http2),
                        },
                        inner: TcpRoute {
                            address: UnresolvedHost("front-sni1".into()),
                            port: http::DEFAULT_HTTPS_PORT,
                        },
                    },
                },
            },
            WebSocketRoute {
                fragment: WebSocketRouteFragment {
                    ws_config: WebSocketConfig::default(),
                    endpoint: WS_ENDPOINT.clone(),
                },
                inner: HttpsTlsRoute {
                    fragment: HttpRouteFragment {
                        host_header: "front-host".into(),
                    },
                    inner: TlsRoute {
                        fragment: TlsRouteFragment {
                            root_certs: RootCertificates::Native,
                            sni: Some("front-sni2".into()),
                            alpn: Some(Alpn::Http2),
                        },
                        inner: TcpRoute {
                            address: UnresolvedHost("front-sni2".into()),
                            port: DEFAULT_HTTPS_PORT,
                        },
                    },
                },
            },
        ];

        pretty_assertions::assert_eq!(routes, expected_routes)
    }

    #[test]
    fn tls_proxy_route() {
        const TARGET_PORT: NonZeroU16 = nonzero!(7898u16);
        const PROXY_PORT: NonZeroU16 = nonzero!(13u16);
        const PROXY_CERTS: RootCertificates = RootCertificates::FromDer(Cow::Borrowed(b"proxy"));

        let direct_provider = TlsRouteProvider {
            sni: Some("direct-sni".into()),
            certs: ROOT_CERTS.clone(),
            inner: DirectTcpRouteProvider {
                dns_hostname: "direct-target".into(),
                port: TARGET_PORT,
            },
        };

        let provider = ConnectionProxyRouteProvider {
            proxy: ConnectionProxyConfig::TlsProxy {
                proxy_host: Host::Domain("tls-proxy".into()),
                proxy_port: PROXY_PORT,
                proxy_certs: PROXY_CERTS,
            },
            inner: direct_provider,
        };

        let routes = provider.routes().collect_vec();

        assert_eq!(
            routes,
            vec![TlsRoute {
                fragment: TlsRouteFragment {
                    root_certs: ROOT_CERTS.clone(),
                    sni: Some("direct-sni".into()),
                    alpn: None,
                },
                inner: ConnectionProxyRoute::Tls {
                    proxy: TlsRoute {
                        inner: TcpRoute {
                            address: Host::Domain(UnresolvedHost("tls-proxy".into())),
                            port: PROXY_PORT,
                        },
                        fragment: TlsRouteFragment {
                            root_certs: PROXY_CERTS.clone(),
                            sni: Some("tls-proxy".into()),
                            alpn: None,
                        },
                    },
                },
            }]
        );
    }

    #[test]
    fn socks_proxy_route() {
        const TARGET_PORT: NonZeroU16 = nonzero!(7898u16);
        const PROXY_PORT: NonZeroU16 = nonzero!(13u16);
        const SOCKS_PROTOCOL: socks::Protocol = socks::Protocol::Socks5 {
            username_password: None,
        };

        let direct_provider = TlsRouteProvider {
            sni: Some("direct-sni".into()),
            certs: ROOT_CERTS.clone(),
            inner: DirectTcpRouteProvider {
                dns_hostname: "direct-target".into(),
                port: TARGET_PORT,
            },
        };

        let provider = ConnectionProxyRouteProvider {
            proxy: ConnectionProxyConfig::Socks {
                proxy_host: Host::Domain("socks-proxy".into()),
                proxy_port: PROXY_PORT,
                protocol: SOCKS_PROTOCOL,
                resolve_hostname_locally: false,
            },
            inner: direct_provider,
        };

        let routes = provider.routes().collect_vec();

        let expected_routes = vec![TlsRoute {
            fragment: TlsRouteFragment {
                root_certs: ROOT_CERTS.clone(),
                sni: Some("direct-sni".into()),
                alpn: None,
            },
            inner: ConnectionProxyRoute::Socks {
                proxy: TcpRoute {
                    address: Host::Domain(UnresolvedHost("socks-proxy".into())),
                    port: PROXY_PORT,
                },
                target_addr: SocksTarget::ResolvedRemotely {
                    name: "direct-target".into(),
                },
                target_port: TARGET_PORT,
                protocol: SOCKS_PROTOCOL,
            },
        }];
        assert_eq!(routes, expected_routes);
    }

    #[test]
    fn connection_proxy_on_top_of_websocket_route_is_provider() {
        // Compilation-only test that makes sure we can wrap a fully-specified
        // websocket route provider with a connection proxy provider.
        fn asserts_route_type<P: RouteProvider<Route = T>, T>() {}
        type MaybeProxyProvider<P> = DirectOrProxyProvider<P, ConnectionProxyRouteProvider<P>>;

        type WsProvider = WebSocketProvider<
            HttpsProvider<DomainFrontRouteProvider, TlsRouteProvider<DirectTcpRouteProvider>>,
        >;

        asserts_route_type::<
            MaybeProxyProvider<WsProvider>,
            WebSocketRoute<
                HttpsTlsRoute<
                    TlsRoute<
                        DirectOrProxyRoute<
                            TcpRoute<UnresolvedHost>,
                            ConnectionProxyRoute<Host<UnresolvedHost>>,
                        >,
                    >,
                >,
            >,
        >();
    }
}
