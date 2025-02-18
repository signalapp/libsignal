//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU16;
use std::sync::Arc;

use either::Either;
use nonzero_ext::nonzero;

use crate::certs::RootCertificates;
use crate::errors::LogSafeDisplay;
use crate::host::Host;
use crate::route::{
    ReplaceFragment, RouteProvider, RouteProviderContext, SimpleRoute, TcpRoute, TlsRoute,
    TlsRouteFragment, UnresolvedHost,
};
use crate::tcp_ssl::proxy::socks;
use crate::Alpn;

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

#[derive(Clone, Debug, PartialEq, Eq, Hash, strum::EnumDiscriminants)]
#[strum_discriminants(name(ConnectionProxyKind))]
pub enum ConnectionProxyRoute<Addr> {
    Tls {
        proxy: TlsRoute<TcpRoute<Addr>>,
    },
    /// TCP proxy without encryption, only for testing.
    Tcp {
        proxy: TcpRoute<Addr>,
    },
    Socks(SocksRoute<Addr>),
    Https(HttpsProxyRoute<Addr>),
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

/// [`RouteProvider`] implementation that returns [`DirectOrProxyRoute`]s.
///
/// Constructs routes that either connect directly or through a proxy.
#[derive(Clone, Debug, PartialEq)]
pub enum DirectOrProxyProvider<D, P> {
    Direct(D),
    Proxy(P),
}

#[derive(Debug, Clone)]
pub struct TlsProxy {
    pub proxy_host: Host<Arc<str>>,
    pub proxy_port: NonZeroU16,
    pub proxy_certs: RootCertificates,
}

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

#[derive(Debug, Clone, derive_more::From)]
pub enum ConnectionProxyConfig {
    Tls(TlsProxy),
    Tcp(TcpProxy),
    Socks(SocksProxy),
    Http(HttpProxy),
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
                if auth
                    .as_ref()
                    .is_some_and(|auth| auth.username == "UNENCRYPTED_FOR_TESTING")
                {
                    // This is a testing interface only; we don't have to be super strict about it
                    // because it should be obvious from the username not to use it in general.
                    TcpProxy {
                        proxy_host: host,
                        proxy_port: port.unwrap_or(nonzero!(80u16)),
                    }
                    .into()
                } else {
                    if auth.is_some() {
                        return Err(ProxyFromPartsError::SchemeDoesNotSupportUsernames(
                            SIGNAL_TLS_PROXY_SCHEME,
                        ));
                    }
                    TlsProxy {
                        proxy_host: host,
                        proxy_port: port.unwrap_or(nonzero!(443u16)),
                        proxy_certs: CERTS_FOR_ARBITRARY_PROXY,
                    }
                    .into()
                }
            }
            "http" => HttpProxy {
                proxy_host: host,
                proxy_port: port.unwrap_or(nonzero!(80u16)),
                proxy_tls: None,
                proxy_authorization: auth,
                resolve_hostname_locally: true,
            }
            .into(),
            "https" => HttpProxy {
                proxy_host: host,
                proxy_port: port.unwrap_or(nonzero!(443u16)),
                proxy_tls: Some(CERTS_FOR_ARBITRARY_PROXY),
                proxy_authorization: auth,
                resolve_hostname_locally: true,
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
}

pub struct ConnectionProxyRouteProvider<P> {
    pub(crate) proxy: ConnectionProxyConfig,
    pub(crate) inner: P,
}

impl<D> DirectOrProxyProvider<D, ConnectionProxyRouteProvider<D>> {
    /// Convenience constructor for a provider that creates proxied routes if a
    /// config is provided.
    ///
    /// Returns `Self::Direct(direct)` if no proxy config is given, otherwise
    /// `Self::Proxy` with a `ConnectionProxyRouteProvider` wrapped around
    /// `direct`.
    pub fn maybe_proxied(direct: D, proxy_config: Option<ConnectionProxyConfig>) -> Self {
        match proxy_config {
            Some(proxy) => Self::Proxy(ConnectionProxyRouteProvider::new(proxy, direct)),
            None => Self::Direct(direct),
        }
    }
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
    D: RouteProvider<
        Route: ReplaceFragment<TcpRoute<UnresolvedHost>, Replacement<DirectOrProxyReplacement> = R>,
    >,
    P: RouteProvider<
        Route: ReplaceFragment<
            ConnectionProxyRoute<Host<UnresolvedHost>>,
            Replacement<DirectOrProxyReplacement> = R,
        >,
    >,
{
    type Route = R;

    fn routes<'s>(
        &'s self,
        context: &impl RouteProviderContext,
    ) -> impl Iterator<Item = Self::Route> + 's {
        match self {
            Self::Direct(direct) => Either::Left(
                direct
                    .routes(context)
                    .map(|route: D::Route| route.replace(DirectOrProxyRoute::Direct)),
            ),
            Self::Proxy(proxy) => Either::Right(proxy.routes(context).map(|route: P::Route| {
                route.replace(|cpr: ConnectionProxyRoute<Host<UnresolvedHost>>| {
                    DirectOrProxyRoute::Proxy(cpr)
                })
            })),
        }
    }
}

impl<P> RouteProvider for ConnectionProxyRouteProvider<P>
where
    P: RouteProvider<Route: ReplaceFragment<TcpRoute<UnresolvedHost>>>,
{
    type Route = <P::Route as ReplaceFragment<TcpRoute<UnresolvedHost>>>::Replacement<
        ConnectionProxyRoute<Host<UnresolvedHost>>,
    >;

    fn routes<'s>(
        &'s self,
        context: &impl RouteProviderContext,
    ) -> impl Iterator<Item = Self::Route> + 's {
        let Self { proxy, inner } = self;
        let replacer = proxy.as_replacer();
        inner.routes(context).map(replacer)
    }
}

trait AsReplacer {
    fn as_replacer<R: ReplaceFragment<TcpRoute<UnresolvedHost>>>(
        &self,
    ) -> impl Fn(R) -> R::Replacement<ConnectionProxyRoute<Host<UnresolvedHost>>>;
}

impl AsReplacer for ConnectionProxyConfig {
    fn as_replacer<R: ReplaceFragment<TcpRoute<UnresolvedHost>>>(
        &self,
    ) -> impl Fn(R) -> R::Replacement<ConnectionProxyRoute<Host<UnresolvedHost>>> {
        let replacer = match self {
            ConnectionProxyConfig::Tls(tls_proxy) => {
                Either::Left(Either::Left(tls_proxy.as_replacer()))
            }
            ConnectionProxyConfig::Tcp(tcp_proxy) => {
                Either::Right(Either::Left(tcp_proxy.as_replacer()))
            }
            ConnectionProxyConfig::Socks(socks_proxy) => {
                Either::Right(Either::Right(socks_proxy.as_replacer()))
            }
            ConnectionProxyConfig::Http(http_proxy) => {
                Either::Left(Either::Right(http_proxy.as_replacer()))
            }
        };
        move |route| match &replacer {
            Either::Left(Either::Left(f)) => f(route),
            Either::Left(Either::Right(f)) => f(route),
            Either::Right(Either::Left(f)) => f(route),
            Either::Right(Either::Right(f)) => f(route),
        }
    }
}

impl AsReplacer for TcpProxy {
    fn as_replacer<R: ReplaceFragment<TcpRoute<UnresolvedHost>>>(
        &self,
    ) -> impl Fn(R) -> R::Replacement<ConnectionProxyRoute<Host<UnresolvedHost>>> {
        let Self {
            proxy_host,
            proxy_port,
        } = self;

        let tcp = TcpRoute {
            address: match proxy_host {
                Host::Ip(ip) => Host::Ip(*ip),
                Host::Domain(domain) => Host::Domain(UnresolvedHost(Arc::clone(domain))),
            },
            port: *proxy_port,
        };

        move |route| {
            route.replace(|_: TcpRoute<UnresolvedHost>| ConnectionProxyRoute::Tcp {
                proxy: tcp.clone(),
            })
        }
    }
}

impl AsReplacer for TlsProxy {
    fn as_replacer<R: ReplaceFragment<TcpRoute<UnresolvedHost>>>(
        &self,
    ) -> impl Fn(R) -> R::Replacement<ConnectionProxyRoute<Host<UnresolvedHost>>> {
        let Self {
            proxy_host,
            proxy_port,
            proxy_certs,
        } = self;
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
        move |route| {
            route.replace(|_: TcpRoute<UnresolvedHost>| ConnectionProxyRoute::Tls {
                proxy: tls_route.clone(),
            })
        }
    }
}

impl AsReplacer for SocksProxy {
    fn as_replacer<R: ReplaceFragment<TcpRoute<UnresolvedHost>>>(
        &self,
    ) -> impl Fn(R) -> R::Replacement<ConnectionProxyRoute<Host<UnresolvedHost>>> {
        let Self {
            proxy_host,
            proxy_port,
            protocol,
            resolve_hostname_locally,
        } = self;
        let proxy = TcpRoute {
            address: match proxy_host {
                Host::Ip(ip_addr) => Host::Ip(*ip_addr),
                Host::Domain(domain) => Host::Domain(UnresolvedHost(Arc::clone(domain))),
            },
            port: *proxy_port,
        };
        move |route| {
            route.replace(|TcpRoute { address, port }| {
                ConnectionProxyRoute::Socks(SocksRoute {
                    proxy: proxy.clone(),
                    protocol: protocol.clone(),
                    target_addr: if *resolve_hostname_locally {
                        ProxyTarget::ResolvedLocally(Host::Domain(address))
                    } else {
                        ProxyTarget::ResolvedRemotely { name: address.0 }
                    },
                    target_port: port,
                })
            })
        }
    }
}

impl AsReplacer for HttpProxy {
    fn as_replacer<R: ReplaceFragment<TcpRoute<UnresolvedHost>>>(
        &self,
    ) -> impl Fn(R) -> R::Replacement<ConnectionProxyRoute<Host<UnresolvedHost>>> {
        let Self {
            proxy_host,
            proxy_port,
            resolve_hostname_locally,
            proxy_authorization,
            proxy_tls,
        } = self;
        let proxy_tcp_route = TcpRoute {
            address: proxy_host.clone().map_domain(UnresolvedHost::from),
            port: *proxy_port,
        };
        let inner_route = match proxy_tls {
            Some(proxy_certs) => Either::Left(TlsRoute {
                inner: proxy_tcp_route,
                fragment: TlsRouteFragment {
                    root_certs: proxy_certs.clone(),
                    sni: proxy_host.clone(),
                    alpn: Some(Alpn::Http1_1),
                },
            }),
            None => Either::Right(proxy_tcp_route),
        };
        move |route| {
            route.replace(|TcpRoute { address, port }| {
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
                    inner: inner_route.clone(),
                })
            })
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
        assert!(
            resolve_hostname_locally,
            "this endpoint never produces a config that defers to the proxy"
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
