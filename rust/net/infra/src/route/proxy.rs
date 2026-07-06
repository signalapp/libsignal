//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU16;
use std::sync::Arc;

use either::Either;
use http::uri::PathAndQuery;
use itertools::Itertools as _;
use libsignal_core::LogSafeDisplay;
use nonzero_ext::nonzero;

use crate::certs::RootCertificates;
use crate::host::Host;
use crate::route::{
    DEFAULT_HTTPS_PORT, HttpRouteFragment, HttpVersion, HttpsTlsRoute, ReplaceFragment,
    RouteProvider, RouteProviderContext, SimpleRoute, TcpRoute, TlsRoute, TlsRouteFragment,
    UnresolvedHost, WebSocketRoute, WebSocketRouteFragment,
};
use crate::tcp_ssl::proxy::socks;
use crate::{Alpn, RouteType};

pub const SIGNAL_TLS_PROXY_SCHEME: &str = "org.signal.tls";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SocksRoute<Addr> {
    pub proxy: TcpRoute<Addr>,
    pub target_addr: ProxyTarget<Addr>,
    pub target_port: NonZeroU16,
    pub protocol: socks::Protocol,
}

/// Route for connecting via an HTTPS proxy.
pub type HttpsProxyRoute<Addr> =
    SimpleRoute<HttpProxyRouteFragment<Addr>, Either<TlsRoute<TcpRoute<Addr>>, TcpRoute<Addr>>>;

/// Required information for an HTTP [CONNECT](::http::method::Method::CONNECT)
/// request.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HttpProxyRouteFragment<Addr> {
    /// The address to pass to the proxy as the target.
    pub target_host: ProxyTarget<Addr>,
    /// The port on the target (to pass to the proxy).
    pub target_port: NonZeroU16,
    /// An authorization header to pass to the proxy.
    pub authorization: Option<HttpProxyAuth>,
}

/// Username and password to pass to an HTTP proxy.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HttpProxyAuth {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ReflectorProxyRoute<Addr> {
    pub outer: WebSocketRoute<HttpsTlsRoute<TlsRoute<TcpRoute<Addr>>>>,
    pub target_host: Arc<str>,
    pub target_port: NonZeroU16,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, strum::EnumDiscriminants)]
#[strum_discriminants(name(ConnectionProxyKind))]
pub enum ConnectionProxyRoute<Addr> {
    Tls {
        proxy: TlsRoute<TcpRoute<Addr>>,
    },
    #[cfg(feature = "dev-util")]
    /// TCP proxy without encryption, only for testing.
    Tcp {
        proxy: TcpRoute<Addr>,
    },
    Socks(SocksRoute<Addr>),
    Https(HttpsProxyRoute<Addr>),
    // Boxed because it's much larger than the other variants.
    Reflector(Box<ReflectorProxyRoute<Addr>>),
}

/// Target address for proxy protocols that support remote resolution.
///
/// SOCKS and HTTPS proxies support making a connection to a remote host
/// specified as an IP address or as a domain name; in the latter case the proxy
/// will resolve the name itself. The distinction is important: when local DNS
/// requests are being blocked, connecting to a remotely-resolved name might
/// still work.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ProxyTarget<Addr> {
    /// A target that will be resolved locally and communicated to the proxy as
    /// an IP address.
    ResolvedLocally(Addr),
    /// A domain name target that the proxy will resolve for itself.
    ResolvedRemotely { name: Arc<str> },
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum DirectOrProxyRoute<D, P> {
    Direct(D),
    Proxy(P),
}

#[derive(Clone, Debug, strum::EnumDiscriminants)]
#[strum_discriminants(derive(strum::Display))]
pub enum DirectOrProxyMode {
    DirectOnly,
    ProxyOnly(ConnectionProxyConfig),
    ProxyThenDirect(ConnectionProxyConfig),
    DirectThenProxy(ConnectionProxyConfig),
}

impl std::fmt::Display for DirectOrProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = DirectOrProxyModeDiscriminants::from(self);
        match self {
            DirectOrProxyMode::DirectOnly => write!(f, "{kind}"),
            DirectOrProxyMode::ProxyOnly(proxy)
            | DirectOrProxyMode::ProxyThenDirect(proxy)
            | DirectOrProxyMode::DirectThenProxy(proxy) => {
                write!(f, "{kind}({})", proxy.log_safe_kind())
            }
        }
    }
}

impl LogSafeDisplay for DirectOrProxyMode {}

/// [`RouteProvider`] implementation that returns [`DirectOrProxyRoute`]s.
///
/// Constructs routes that either connect directly or through a proxy.
#[derive(Clone, Debug)]
pub struct DirectOrProxyProvider<D> {
    pub inner: D,
    pub mode: DirectOrProxyMode,
}

#[derive(Debug, Clone)]
pub struct TlsProxy {
    pub proxy_host: Host<Arc<str>>,
    pub proxy_port: NonZeroU16,
    pub proxy_certs: RootCertificates,
}

#[cfg(feature = "dev-util")]
#[derive(Debug, Clone)]
pub struct TcpProxy {
    pub proxy_host: Host<Arc<str>>,
    pub proxy_port: NonZeroU16,
}

#[derive(Debug, Clone)]
pub struct SocksProxy {
    pub proxy_host: Host<Arc<str>>,
    pub proxy_port: NonZeroU16,
    pub protocol: socks::Protocol,
    pub resolve_hostname_locally: bool,
}

#[derive(Debug, Clone)]
pub struct HttpProxy {
    pub proxy_host: Host<Arc<str>>,
    pub proxy_port: NonZeroU16,
    pub proxy_tls: Option<RootCertificates>,
    pub proxy_authorization: Option<HttpProxyAuth>,
    pub resolve_hostname_locally: bool,
}

#[derive(Debug, Clone, derive_more::From, strum::IntoStaticStr)]
pub enum ConnectionProxyConfig {
    Tls(TlsProxy),
    #[cfg(feature = "dev-util")]
    Tcp(TcpProxy),
    Socks(SocksProxy),
    Http(HttpProxy),
    /// Reflector tunnel providers to try. The caller is expected to take this
    /// slice from the surrounding environment/domain config so prod and staging
    /// can't be mispaired.
    Reflector(&'static [ReflectorProviderConfig]),
}

#[derive(Debug)]
pub struct ReflectorProviderConfig {
    pub route_type: RouteType,
    pub http_host: &'static str,
    /// Pool of candidate SNI hostnames; one is selected per connection attempt.
    pub sni_list: &'static [&'static str],
    pub certs: RootCertificates,
    pub endpoint: PathAndQuery,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ProxyFromPartsError {
    /// missing host
    MissingHost,
    /// libsignal does not support proxying via '{0}'
    UnsupportedScheme(String),
    /// '{0}' proxies do not support usernames
    SchemeDoesNotSupportUsernames(&'static str),
    /// '{0}' proxies do not support passwords
    SchemeDoesNotSupportPasswords(&'static str),
}

impl LogSafeDisplay for ProxyFromPartsError {}

impl ConnectionProxyConfig {
    fn log_safe_kind(&self) -> &'static str {
        self.into()
    }

    /// Create a ConnectionProxyConfig from the information found in a URL or PAC file.
    ///
    /// Passing `None` for the `port` means the default port for the proxy type will be used.
    ///
    /// Not all types of proxies support authentication. For those that support usernames but not
    /// passwords, the second element of the `auth` tuple must be empty.
    pub fn from_parts(
        scheme: &str,
        host: &str,
        port: Option<NonZeroU16>,
        auth: Option<(String, String)>,
    ) -> Result<Self, ProxyFromPartsError> {
        if host.is_empty() {
            return Err(ProxyFromPartsError::MissingHost);
        }

        let host = Host::parse_as_ip_or_domain(host);
        let auth = auth.map(|(username, password)| HttpProxyAuth { username, password });

        // Proxies that use TLS are permitted to use any valid certificate, not just our pinned
        // ones, so we have to defer to the system trust store.
        const CERTS_FOR_ARBITRARY_PROXY: RootCertificates = RootCertificates::Native;

        let proxy: ConnectionProxyConfig = match scheme {
            SIGNAL_TLS_PROXY_SCHEME => {
                match auth {
                    #[cfg(feature = "dev-util")]
                    Some(auth) if auth.username == "UNENCRYPTED_FOR_TESTING" => {
                        // This is a testing interface only; we don't have to be super strict about it
                        // because it should be obvious from the username not to use it in general.
                        TcpProxy {
                            proxy_host: host,
                            proxy_port: port.unwrap_or(nonzero!(80u16)),
                        }
                        .into()
                    }
                    Some(_) => {
                        return Err(ProxyFromPartsError::SchemeDoesNotSupportUsernames(
                            SIGNAL_TLS_PROXY_SCHEME,
                        ));
                    }
                    None => TlsProxy {
                        proxy_host: host,
                        proxy_port: port.unwrap_or(nonzero!(443u16)),
                        proxy_certs: CERTS_FOR_ARBITRARY_PROXY,
                    }
                    .into(),
                }
            }
            "http" => HttpProxy {
                proxy_host: host,
                proxy_port: port.unwrap_or(nonzero!(80u16)),
                proxy_tls: None,
                proxy_authorization: auth,
                resolve_hostname_locally: false,
            }
            .into(),
            "https" => HttpProxy {
                proxy_host: host,
                proxy_port: port.unwrap_or(nonzero!(443u16)),
                proxy_tls: Some(CERTS_FOR_ARBITRARY_PROXY),
                proxy_authorization: auth,
                resolve_hostname_locally: false,
            }
            .into(),
            "socks4" | "socks4a" => {
                if auth.as_ref().is_some_and(|auth| !auth.password.is_empty()) {
                    return Err(ProxyFromPartsError::SchemeDoesNotSupportPasswords("socks4"));
                }
                SocksProxy {
                    proxy_host: host,
                    proxy_port: port.unwrap_or(nonzero!(1080u16)),
                    protocol: socks::Protocol::Socks4 {
                        user_id: auth.map(|auth| auth.username),
                    },
                    resolve_hostname_locally: scheme != "socks4a",
                }
            }
            .into(),
            "socks" | "socks5" | "socks5h" => SocksProxy {
                proxy_host: host,
                proxy_port: port.unwrap_or(nonzero!(1080u16)),
                protocol: socks::Protocol::Socks5 {
                    username_password: auth.map(|auth| (auth.username, auth.password)),
                },
                resolve_hostname_locally: scheme != "socks5h",
            }
            .into(),
            scheme => {
                return Err(ProxyFromPartsError::UnsupportedScheme(scheme.to_owned()));
            }
        };

        Ok(proxy)
    }

    pub fn is_signal_transparent_proxy(&self) -> bool {
        match self {
            Self::Tls(_) => true,
            #[cfg(feature = "dev-util")]
            Self::Tcp(_) => true,
            Self::Socks(_) | Self::Http(_) | Self::Reflector(_) => false,
        }
    }
}

impl<D> DirectOrProxyProvider<D> {
    /// Convenience constructor for direct connections.
    pub fn direct(inner: D) -> Self {
        Self {
            inner,
            mode: DirectOrProxyMode::DirectOnly,
        }
    }
}

impl DirectOrProxyMode {
    /// Convenience constructor [`DirectOnly`] or [`ProxyOnly`]
    ///
    /// [`DirectOnly`]: DirectOrProxyMode::DirectOnly
    /// [`ProxyOnly`]: DirectOrProxyMode::ProxyOnly
    pub fn maybe_proxy(proxy: Option<ConnectionProxyConfig>) -> Self {
        proxy.map_or(Self::DirectOnly, Self::ProxyOnly)
    }

    pub fn proxy_config(&self) -> Option<&ConnectionProxyConfig> {
        match self {
            Self::DirectOnly => None,
            Self::ProxyOnly(p) | Self::ProxyThenDirect(p) | Self::DirectThenProxy(p) => Some(p),
        }
    }
}

type DirectOrProxyReplacement =
    DirectOrProxyRoute<TcpRoute<UnresolvedHost>, ConnectionProxyRoute<Host<UnresolvedHost>>>;
type UnresolvedConnectionProxyRoute = ConnectionProxyRoute<Host<UnresolvedHost>>;

impl<D, R: 'static> RouteProvider for DirectOrProxyProvider<D>
where
    D: RouteProvider<
        Route: ReplaceFragment<
            TcpRoute<UnresolvedHost>,
            Replacement<DirectOrProxyReplacement> = R,
        > + Clone,
    >,
{
    type Route = R;

    fn routes<'s, C: RouteProviderContext>(
        &'s self,
        context: &mut C,
    ) -> impl Iterator<Item = Self::Route> + use<'s, C, D, R> {
        let Self { inner, mode } = self;
        match mode {
            DirectOrProxyMode::DirectOnly => Either::Left(
                inner
                    .routes(context)
                    .map(|r| r.replace(DirectOrProxyRoute::Direct)),
            ),
            DirectOrProxyMode::ProxyOnly(proxy)
            | DirectOrProxyMode::ProxyThenDirect(proxy)
            | DirectOrProxyMode::DirectThenProxy(proxy) => {
                let original_routes = inner.routes(context).collect_vec();
                let proxy_providers = proxy.concrete_proxy_configs(context);
                let proxied_routes = proxy_providers
                    .into_iter()
                    .flat_map(|provider| {
                        original_routes
                            .iter()
                            .cloned()
                            .map(move |route| provider.replace_route(route))
                    })
                    .collect_vec();

                let routes = match mode {
                    DirectOrProxyMode::ProxyOnly(_) => proxied_routes,
                    DirectOrProxyMode::ProxyThenDirect(_) => proxied_routes
                        .into_iter()
                        .chain(
                            original_routes
                                .into_iter()
                                .map(|r| r.replace(DirectOrProxyRoute::Direct)),
                        )
                        .collect(),
                    DirectOrProxyMode::DirectThenProxy(_) => original_routes
                        .into_iter()
                        .map(|r| r.replace(DirectOrProxyRoute::Direct))
                        .chain(proxied_routes)
                        .collect(),
                    DirectOrProxyMode::DirectOnly => unreachable!("handled above"),
                };

                Either::Right(routes.into_iter())
            }
        }
    }
}

impl ConnectionProxyConfig {
    fn concrete_proxy_configs<C: RouteProviderContext>(
        &self,
        context: &mut C,
    ) -> Vec<ConcreteProxyConfig<'_>> {
        match self {
            Self::Tls(tls_proxy) => vec![ConcreteProxyConfig::Tls(tls_proxy)],
            #[cfg(feature = "dev-util")]
            Self::Tcp(tcp_proxy) => vec![ConcreteProxyConfig::Tcp(tcp_proxy)],
            Self::Socks(socks_proxy) => vec![ConcreteProxyConfig::Socks(socks_proxy)],
            Self::Http(http_proxy) => vec![ConcreteProxyConfig::Http(http_proxy)],
            Self::Reflector(providers) => {
                let sni_index = context.random_usize();
                providers
                    .iter()
                    .map(|provider| ConcreteProxyConfig::Reflector(provider.pick_sni(sni_index)))
                    .collect()
            }
        }
    }
}

#[derive(Clone)]
struct ConcreteReflectorRouteProvider {
    route_type: RouteType,
    http_host: &'static str,
    sni: &'static str,
    certs: RootCertificates,
    endpoint: PathAndQuery,
}

impl ReflectorProviderConfig {
    fn pick_sni(&self, sni_index: usize) -> ConcreteReflectorRouteProvider {
        assert!(
            !self.sni_list.is_empty(),
            "ReflectorProviderConfig::sni_list must not be empty"
        );
        ConcreteReflectorRouteProvider {
            route_type: self.route_type,
            http_host: self.http_host,
            sni: self.sni_list[sni_index % self.sni_list.len()],
            certs: self.certs.clone(),
            endpoint: self.endpoint.clone(),
        }
    }
}

#[derive(Clone)]
enum ConcreteProxyConfig<'a> {
    Tls(&'a TlsProxy),
    #[cfg(feature = "dev-util")]
    Tcp(&'a TcpProxy),
    Socks(&'a SocksProxy),
    Http(&'a HttpProxy),
    Reflector(ConcreteReflectorRouteProvider),
}

impl ConcreteProxyConfig<'_> {
    fn replace_route<R>(&self, route: R) -> R::Replacement<DirectOrProxyReplacement>
    where
        R: ReplaceFragment<TcpRoute<UnresolvedHost>>,
    {
        route.replace(|tcp_route| DirectOrProxyRoute::Proxy(self.to_proxy_route(tcp_route)))
    }

    fn to_proxy_route(
        &self,
        tcp_route: TcpRoute<UnresolvedHost>,
    ) -> UnresolvedConnectionProxyRoute {
        match self {
            Self::Tls(TlsProxy {
                proxy_host,
                proxy_port,
                proxy_certs,
            }) => ConnectionProxyRoute::Tls {
                proxy: TlsRoute {
                    inner: TcpRoute {
                        address: proxy_host_as_unresolved(proxy_host),
                        port: *proxy_port,
                        override_nagle_algorithm: tcp_route.override_nagle_algorithm,
                    },
                    fragment: TlsRouteFragment {
                        root_certs: proxy_certs.clone(),
                        sni: proxy_host.clone(),
                        alpn: None,
                        min_protocol_version: None,
                    },
                },
            },

            #[cfg(feature = "dev-util")]
            Self::Tcp(TcpProxy {
                proxy_host,
                proxy_port,
            }) => ConnectionProxyRoute::Tcp {
                proxy: TcpRoute {
                    address: proxy_host_as_unresolved(proxy_host),
                    port: *proxy_port,
                    override_nagle_algorithm: tcp_route.override_nagle_algorithm,
                },
            },

            Self::Socks(SocksProxy {
                proxy_host,
                proxy_port,
                protocol,
                resolve_hostname_locally,
            }) => {
                let TcpRoute {
                    address,
                    port,
                    override_nagle_algorithm,
                } = tcp_route;
                ConnectionProxyRoute::Socks(SocksRoute {
                    proxy: TcpRoute {
                        address: proxy_host_as_unresolved(proxy_host),
                        port: *proxy_port,
                        override_nagle_algorithm,
                    },
                    protocol: protocol.clone(),
                    target_addr: if *resolve_hostname_locally {
                        ProxyTarget::ResolvedLocally(Host::Domain(address))
                    } else {
                        ProxyTarget::ResolvedRemotely { name: address.0 }
                    },
                    target_port: port,
                })
            }

            Self::Http(HttpProxy {
                proxy_host,
                proxy_port,
                proxy_tls,
                proxy_authorization,
                resolve_hostname_locally,
            }) => {
                let TcpRoute {
                    address,
                    port,
                    override_nagle_algorithm,
                } = tcp_route;
                ConnectionProxyRoute::Https(HttpsProxyRoute {
                    fragment: HttpProxyRouteFragment {
                        target_host: if *resolve_hostname_locally {
                            ProxyTarget::ResolvedLocally(Host::Domain(address))
                        } else {
                            ProxyTarget::ResolvedRemotely { name: address.0 }
                        },
                        target_port: port,
                        authorization: proxy_authorization.clone(),
                    },
                    inner: {
                        let proxy_tcp = TcpRoute {
                            address: proxy_host.clone().map_domain(UnresolvedHost::from),
                            port: *proxy_port,
                            override_nagle_algorithm,
                        };
                        match proxy_tls {
                            Some(proxy_certs) => Either::Left(TlsRoute {
                                inner: proxy_tcp,
                                fragment: TlsRouteFragment {
                                    root_certs: proxy_certs.clone(),
                                    sni: proxy_host.clone(),
                                    alpn: Some(Alpn::Http1_1),
                                    min_protocol_version: None,
                                },
                            }),
                            None => Either::Right(proxy_tcp),
                        }
                    },
                })
            }

            Self::Reflector(ConcreteReflectorRouteProvider {
                route_type,
                http_host,
                sni,
                certs,
                endpoint,
            }) => ConnectionProxyRoute::Reflector(Box::new(ReflectorProxyRoute {
                outer: WebSocketRoute {
                    fragment: WebSocketRouteFragment {
                        ws_config: Default::default(),
                        endpoint: endpoint.clone(),
                        headers: Default::default(),
                    },
                    inner: HttpsTlsRoute {
                        fragment: HttpRouteFragment {
                            host_header: (*http_host).into(),
                            path_prefix: "".into(),
                            http_version: Some(HttpVersion::Http1_1),
                            front_name: Some((*route_type).into()),
                        },
                        inner: TlsRoute {
                            fragment: TlsRouteFragment {
                                root_certs: certs.clone(),
                                sni: Host::Domain((*sni).into()),
                                alpn: Some(Alpn::Http1_1),
                                min_protocol_version: None,
                            },
                            inner: TcpRoute {
                                address: Host::Domain(UnresolvedHost((*sni).into())),
                                port: DEFAULT_HTTPS_PORT,
                                override_nagle_algorithm: tcp_route.override_nagle_algorithm,
                            },
                        },
                    },
                },
                target_host: tcp_route.address.0,
                target_port: tcp_route.port,
            })),
        }
    }
}

fn proxy_host_as_unresolved(proxy_host: &Host<Arc<str>>) -> Host<UnresolvedHost> {
    proxy_host
        .as_ref()
        .map_domain(|domain| UnresolvedHost(domain.clone()))
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

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use const_str::ip_addr;
    use test_case::test_case;

    use super::*;

    const EXAMPLE_HOST: &str = "proxy.example";

    #[test_case(EXAMPLE_HOST, None, Host::Domain(EXAMPLE_HOST); "simple")]
    #[test_case(EXAMPLE_HOST, Some(4433), Host::Domain(EXAMPLE_HOST); "with port")]
    #[test_case("127.0.0.1", None, ip_addr!("127.0.0.1"); "IPv4")]
    #[test_case("127.0.0.1", Some(4433), ip_addr!("127.0.0.1"); "IPv4 with port")]
    #[test_case("[::1]", None, ip_addr!("::1"); "bracketed IPv6")]
    #[test_case("[::1]", Some(4433), ip_addr!("::1"); "bracketed IPv6 with port")]
    #[test_case("::1", None, ip_addr!("::1"); "unbracketed IPv6 for backwards compatibility")]
    fn proxy_from_parts_signal_tls(
        host: &str,
        port: Option<u16>,
        expected_host: impl Into<Host<&'static str>>,
    ) {
        let TlsProxy {
            proxy_host,
            proxy_port,
            proxy_certs,
        } = {
            let port = port.map(|p| NonZeroU16::try_from(p).expect("valid for testing"));
            assert_matches!(
                ConnectionProxyConfig::from_parts(SIGNAL_TLS_PROXY_SCHEME, host, port, None),
                Ok(ConnectionProxyConfig::Tls(tls)) => tls
            )
        };
        assert_eq!(expected_host.into(), proxy_host.as_deref());
        assert_eq!(port.unwrap_or(443), proxy_port.get());
        assert_matches!(proxy_certs, RootCertificates::Native);
    }

    #[cfg(feature = "dev-util")]
    #[test_case(EXAMPLE_HOST, None, Some("UNENCRYPTED_FOR_TESTING"), Host::Domain(EXAMPLE_HOST); "UNENCRYPTED_FOR_TESTING")]
    #[test_case(EXAMPLE_HOST, Some(8080), Some("UNENCRYPTED_FOR_TESTING"), Host::Domain(EXAMPLE_HOST); "with port")]
    fn proxy_from_parts_signal_tcp(
        host: &str,
        port: Option<u16>,
        auth: Option<&str>,
        expected_host: Host<&str>,
    ) {
        let TcpProxy {
            proxy_host,
            proxy_port,
        } = {
            let port = port.map(|p| NonZeroU16::try_from(p).expect("valid for testing"));
            let auth = auth.map(|u| (u.to_owned(), "".to_owned()));
            assert_matches!(
                ConnectionProxyConfig::from_parts(SIGNAL_TLS_PROXY_SCHEME, host, port, auth),
                Ok(ConnectionProxyConfig::Tcp(tcp)) => tcp
            )
        };
        assert_eq!(expected_host, proxy_host.as_deref());
        assert_eq!(port.unwrap_or(80), proxy_port.get());
    }

    #[test_case("http", EXAMPLE_HOST, None, None, Host::Domain(EXAMPLE_HOST); "simple")]
    #[test_case("https", EXAMPLE_HOST, None, None, Host::Domain(EXAMPLE_HOST); "simple https")]
    #[test_case("http", EXAMPLE_HOST, Some(4433), None, Host::Domain(EXAMPLE_HOST); "with port")]
    #[test_case("https", EXAMPLE_HOST, Some(4433), None, Host::Domain(EXAMPLE_HOST); "with port https")]
    #[test_case("http", EXAMPLE_HOST, None, Some(("user", "")), Host::Domain(EXAMPLE_HOST); "username")]
    #[test_case("http", EXAMPLE_HOST, None, Some(("user", "pass")), Host::Domain(EXAMPLE_HOST); "username + pw")]
    #[test_case("http", "127.0.0.1", None, None, ip_addr!("127.0.0.1"); "IPv4")]
    #[test_case("http", "127.0.0.1", Some(4433), None, ip_addr!("127.0.0.1"); "IPv4 with port")]
    #[test_case("http", "::1", None, None, ip_addr!("::1"); "IPv6")]
    #[test_case("http", "[::1]", None, None, ip_addr!("::1"); "bracketed IPv6")]
    fn proxy_from_parts_signal_http(
        scheme: &str,
        host: &str,
        port: Option<u16>,
        auth: Option<(&str, &str)>,
        expected_host: impl Into<Host<&'static str>>,
    ) {
        let HttpProxy {
            proxy_host,
            proxy_port,
            proxy_tls,
            proxy_authorization,
            resolve_hostname_locally,
        } = {
            let port = port.map(|p| NonZeroU16::try_from(p).expect("valid for testing"));
            let auth = auth.map(|(u, p)| (u.to_owned(), p.to_owned()));
            assert_matches!(
                ConnectionProxyConfig::from_parts(scheme, host, port, auth),
                Ok(ConnectionProxyConfig::Http(http)) => http
            )
        };
        assert_eq!(expected_host.into(), proxy_host.as_deref());
        // This is cheating a bit, but it's simpler than adding another "expected" argument.
        if scheme == "http" {
            assert_eq!(port.unwrap_or(80), proxy_port.get());
            assert_matches!(proxy_tls, None, "http should not use TLS");
        } else {
            assert_eq!(port.unwrap_or(443), proxy_port.get());
            assert_matches!(
                proxy_tls,
                Some(RootCertificates::Native),
                "https should use TLS"
            );
        }
        assert_eq!(
            auth,
            proxy_authorization
                .as_ref()
                .map(|auth| (auth.username.as_str(), auth.password.as_str())),
        );

        // Deferring hostname resolution to the proxy is in line with the published recommendations for
        //   proxy configuration at:
        // https://support.signal.org/hc/en-us/articles/360007320291-Firewall-and-Internet-settings
        assert!(
            !resolve_hostname_locally,
            "we should always defer to the proxy for DNS resolution"
        );
    }

    #[test_case("socks4", EXAMPLE_HOST, None, None, Host::Domain(EXAMPLE_HOST); "simple")]
    #[test_case("socks4a", EXAMPLE_HOST, None, None, Host::Domain(EXAMPLE_HOST); "simple with socks4a")]
    #[test_case("socks4", EXAMPLE_HOST, Some(4433), None, Host::Domain(EXAMPLE_HOST); "with port")]
    #[test_case("socks4", EXAMPLE_HOST, None, Some("user"), Host::Domain(EXAMPLE_HOST); "username")]
    #[test_case("socks4a", EXAMPLE_HOST, Some(4433), Some("user"), Host::Domain(EXAMPLE_HOST); "everything with socks4a")]
    #[test_case("socks4", "127.0.0.1", None, None, ip_addr!("127.0.0.1"); "IPv4")]
    #[test_case("socks4", "::1", None, None, ip_addr!("::1"); "IPv6")]
    #[test_case("socks4", "[::1]", None, None, ip_addr!("::1"); "bracketed IPv6")]
    fn proxy_from_parts_signal_socks4(
        scheme: &str,
        host: &str,
        port: Option<u16>,
        auth: Option<&str>,
        expected_host: impl Into<Host<&'static str>>,
    ) {
        let SocksProxy {
            proxy_host,
            proxy_port,
            protocol,
            resolve_hostname_locally,
        } = {
            let port = port.map(|p| NonZeroU16::try_from(p).expect("valid for testing"));
            let auth = auth.map(|u| (u.to_owned(), "".to_owned()));
            assert_matches!(
                ConnectionProxyConfig::from_parts(scheme, host, port, auth),
                Ok(ConnectionProxyConfig::Socks(socks)) => socks
            )
        };
        assert_eq!(expected_host.into(), proxy_host.as_deref());
        assert_eq!(port.unwrap_or(1080), proxy_port.get());
        let user = assert_matches!(protocol, socks::Protocol::Socks4 { user_id } => user_id);
        assert_eq!(auth, user.as_deref());
        // This is cheating a bit, but it's simpler than adding another "expected" argument.
        if scheme == "socks4a" {
            assert!(
                !resolve_hostname_locally,
                "{scheme} does not resolve hostnames locally"
            );
        } else {
            assert!(
                resolve_hostname_locally,
                "{scheme} resolves hostnames locally"
            );
        }
    }

    #[test_case("socks", EXAMPLE_HOST, None, None, Host::Domain(EXAMPLE_HOST); "simple")]
    #[test_case("socks5", EXAMPLE_HOST, None, None, Host::Domain(EXAMPLE_HOST); "simple with socks5")]
    #[test_case("socks5h", EXAMPLE_HOST, None, None, Host::Domain(EXAMPLE_HOST); "simple with socks5h")]
    #[test_case("socks", EXAMPLE_HOST, Some(4433), None, Host::Domain(EXAMPLE_HOST); "with port")]
    #[test_case("socks", EXAMPLE_HOST, None, Some(("user", "pass")), Host::Domain(EXAMPLE_HOST); "username + pw")]
    #[test_case("socks5h", EXAMPLE_HOST, Some(4433), Some(("user", "pass")), Host::Domain(EXAMPLE_HOST); "everything with socks5h")]
    #[test_case("socks", "127.0.0.1", None, None, ip_addr!("127.0.0.1"); "IPv4")]
    #[test_case("socks", "::1", None, None, ip_addr!("::1"); "IPv6")]
    #[test_case("socks", "[::1]", None, None, ip_addr!("::1"); "bracketed IPv6")]
    fn proxy_from_parts_signal_socks5(
        scheme: &str,
        host: &str,
        port: Option<u16>,
        auth: Option<(&str, &str)>,
        expected_host: impl Into<Host<&'static str>>,
    ) {
        let SocksProxy {
            proxy_host,
            proxy_port,
            protocol,
            resolve_hostname_locally,
        } = {
            let port = port.map(|p| NonZeroU16::try_from(p).expect("valid for testing"));
            let auth = auth.map(|(u, p)| (u.to_owned(), p.to_owned()));
            assert_matches!(
                ConnectionProxyConfig::from_parts(scheme, host, port, auth),
                Ok(ConnectionProxyConfig::Socks(socks)) => socks
            )
        };
        assert_eq!(expected_host.into(), proxy_host.as_deref());
        assert_eq!(port.unwrap_or(1080), proxy_port.get());
        let actual_auth =
            assert_matches!(protocol, socks::Protocol::Socks5 { username_password: auth } => auth);
        assert_eq!(
            auth,
            actual_auth
                .as_ref()
                .map(|auth| (auth.0.as_str(), auth.1.as_str()))
        );
        // This is cheating a bit, but it's simpler than adding another "expected" argument.
        if scheme == "socks5h" {
            assert!(
                !resolve_hostname_locally,
                "{scheme} does not resolve hostnames locally"
            );
        } else {
            assert!(
                resolve_hostname_locally,
                "{scheme} resolves hostnames locally"
            );
        }
    }

    #[test_case("", "", "", "" => matches _)]
    #[test_case("socks", "", "", "" => matches ProxyFromPartsError::MissingHost)]
    #[test_case("garbage", EXAMPLE_HOST, "", "" => matches ProxyFromPartsError::UnsupportedScheme(scheme) if scheme == "garbage")]
    #[test_case("socks4", EXAMPLE_HOST, "user", "pass" => matches ProxyFromPartsError::SchemeDoesNotSupportPasswords("socks4"))]
    #[test_case(SIGNAL_TLS_PROXY_SCHEME, EXAMPLE_HOST, "user", "" => matches ProxyFromPartsError::SchemeDoesNotSupportUsernames(SIGNAL_TLS_PROXY_SCHEME))]
    fn proxy_from_parts_invalid(
        scheme: &str,
        host: &str,
        username: &str,
        password: &str,
    ) -> ProxyFromPartsError {
        let auth = match (username, password) {
            ("", "") => None,
            ("", _) => panic!("invalid test case"),
            _ => Some((username.to_owned(), password.to_owned())),
        };
        let port = None; // no interesting tests for ports, they're all valid

        ConnectionProxyConfig::from_parts(scheme, host, port, auth).expect_err("invalid input")
    }
}
