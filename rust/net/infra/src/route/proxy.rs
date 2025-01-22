//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU16;
use std::str::FromStr as _;
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

const SIGNAL_TLS_PROXY_SCHEME: &str = "org.signal.tls";

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
pub enum ProxyUrlError {
    /// invalid URL: {0}
    InvalidUrl(#[from] url::ParseError),
    /// proxy URL should not include a path
    UnexpectedPath,
    /// proxy URL should not include a query string
    UnexpectedQuery,
    /// proxy URL should not include a fragment
    UnexpectedFragment,
    /// libsignal does not support proxying via '{0}'
    UnsupportedScheme(String),
    /// '{0}' proxies do not support usernames
    SchemeDoesNotSupportUsernames(&'static str),
    /// '{0}' proxies do not support passwords
    SchemeDoesNotSupportPasswords(&'static str),
}

// Assert that `url::ParseError` can't be carrying arbitrary state from the URL that was parsed,
// and therefore can be considered log-safe.
// `std::any::Any` is serving as a check for `'static`, i.e. it doesn't borrow state either.
static_assertions::assert_impl_all!(url::ParseError: Copy, std::any::Any);
impl LogSafeDisplay for ProxyUrlError {}

impl ConnectionProxyConfig {
    pub fn from_url(url_str: &str) -> Result<Self, ProxyUrlError> {
        let url = url::Url::parse(url_str).or_else(|e| {
            // Special case: if someone uses a raw IPv6 address as a Signal-TLS-Proxy domain,
            // manually bracket it and try again. This lets the app layers unconditionally prepend
            // "org.signal.tls://" to the proxies they'd been using in the past.
            const SIGNAL_TLS_PROXY_PREFIX: &str =
                const_str::concat!(SIGNAL_TLS_PROXY_SCHEME, "://");
            if let Some(addr) = url_str
                .strip_prefix(SIGNAL_TLS_PROXY_PREFIX)
                .and_then(|maybe_addr_str| std::net::Ipv6Addr::from_str(maybe_addr_str).ok())
            {
                return url::Url::parse(&format!("{SIGNAL_TLS_PROXY_SCHEME}://[{addr}]"));
            }
            Err(e)
        })?;

        // Let's go through the parts of a URL in order...
        // See https://docs.rs/url/latest/url/ for reference.
        // 1. Scheme (matched at the end)
        let scheme = url.scheme();

        // 2, 3. Username and password
        let auth = if url.username().is_empty() {
            None
        } else {
            Some(HttpProxyAuth {
                username: url.username().to_owned(),
                password: url.password().unwrap_or_default().to_owned(),
            })
        };

        // 4. Host
        let host = match url.host().ok_or(url::ParseError::EmptyHost)? {
            url::Host::Domain(name) => {
                // The URL spec only parses IP addresses if they're using one of the standard web
                // URL schemes (like https), or using bracketed IPv6 syntax. Try harder to support
                // IPv4 here.
                if let Ok(ip) = std::net::Ipv4Addr::from_str(name) {
                    Host::Ip(ip.into())
                } else {
                    Host::Domain(name.into())
                }
            }
            url::Host::Ipv4(addr) => Host::Ip(addr.into()),
            url::Host::Ipv6(addr) => Host::Ip(addr.into()),
        };

        // 5. Port
        let port = url
            .port()
            .map(NonZeroU16::try_from)
            .transpose()
            .map_err(|_| url::ParseError::InvalidPort)?;

        // 6. Path (we only allow a trailing slash, technically unnecessary but if someone types it
        // we know what they mean)
        match url.path() {
            "" | "/" => {}
            _ => {
                return Err(ProxyUrlError::UnexpectedPath);
            }
        }

        // 7, 8. Query and fragment
        if url.query().is_some() {
            return Err(ProxyUrlError::UnexpectedQuery);
        }
        if url.fragment().is_some() {
            return Err(ProxyUrlError::UnexpectedFragment);
        }

        // Proxies that use TLS are permitted to use any valid certificate, not just our pinned
        // ones, so we have to defer to the system trust store.
        const ARBITRARY_PROXY_CERTS: RootCertificates = RootCertificates::Native;

        let proxy: ConnectionProxyConfig = match scheme {
            SIGNAL_TLS_PROXY_SCHEME => {
                if url.username() == "UNENCRYPTED_FOR_TESTING" {
                    // This is a testing interface only; we don't have to be super strict about it
                    // because it should be obvious from the username not to use it in general.
                    TcpProxy {
                        proxy_host: host,
                        proxy_port: port.unwrap_or(nonzero!(80u16)),
                    }
                    .into()
                } else {
                    if auth.is_some() {
                        return Err(ProxyUrlError::SchemeDoesNotSupportUsernames(
                            SIGNAL_TLS_PROXY_SCHEME,
                        ));
                    }
                    TlsProxy {
                        proxy_host: host,
                        proxy_port: port.unwrap_or(nonzero!(443u16)),
                        proxy_certs: ARBITRARY_PROXY_CERTS,
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
                proxy_tls: Some(ARBITRARY_PROXY_CERTS),
                proxy_authorization: auth,
                resolve_hostname_locally: true,
            }
            .into(),
            "socks4" | "socks4a" => {
                if auth.as_ref().is_some_and(|auth| !auth.password.is_empty()) {
                    return Err(ProxyUrlError::SchemeDoesNotSupportPasswords("socks4"));
                }
                SocksProxy {
                    proxy_host: host,
                    proxy_port: port.unwrap_or(nonzero!(1080u16)),
                    protocol: socks::Protocol::Socks4 {
                        user_id: auth.map(|auth| auth.username),
                    },
                    resolve_hostname_locally: url.scheme() != "socks4a",
                }
            }
            .into(),
            "socks" | "socks5" | "socks5h" => SocksProxy {
                proxy_host: host,
                proxy_port: port.unwrap_or(nonzero!(1080u16)),
                protocol: socks::Protocol::Socks5 {
                    username_password: auth.map(|auth| (auth.username, auth.password)),
                },
                resolve_hostname_locally: url.scheme() != "socks5h",
            }
            .into(),
            scheme => {
                return Err(ProxyUrlError::UnsupportedScheme(scheme.to_owned()));
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
    D: RouteProvider,
    P: RouteProvider,
    D::Route: ReplaceFragment<TcpRoute<UnresolvedHost>, Replacement<DirectOrProxyReplacement> = R>,
    P::Route: ReplaceFragment<
        ConnectionProxyRoute<Host<UnresolvedHost>>,
        Replacement<DirectOrProxyReplacement> = R,
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
    P: RouteProvider,
    P::Route: ReplaceFragment<TcpRoute<UnresolvedHost>>,
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

    #[test_case("org.signal.tls://proxy.example", Host::Domain("proxy.example"), 443; "simple")]
    #[test_case("org.signal.tls://proxy.example:4433", Host::Domain("proxy.example"), 4433; "with port")]
    #[test_case("org.signal.tls://127.0.0.1", ip_addr!("127.0.0.1"), 443; "IPv4")]
    #[test_case("org.signal.tls://127.0.0.1:4433", ip_addr!("127.0.0.1"), 4433; "IPv4 with port")]
    #[test_case("org.signal.tls://[::1]", ip_addr!("::1"), 443; "bracketed IPv6")]
    #[test_case("org.signal.tls://[::1]:4433", ip_addr!("::1"), 4433; "bracketed IPv6 with port")]
    #[test_case("org.signal.tls://::1", ip_addr!("::1"), 443; "unbracketed IPv6 for backwards compatibility")]
    fn parse_proxy_signal_tls(
        input: &str,
        expected_host: impl Into<Host<&'static str>>,
        expected_port: u16,
    ) {
        let TlsProxy {
            proxy_host,
            proxy_port,
            proxy_certs,
        } = assert_matches!(
            ConnectionProxyConfig::from_url(input),
            Ok(ConnectionProxyConfig::Tls(tls)) => tls
        );
        assert_eq!(expected_host.into(), proxy_host.as_deref());
        assert_eq!(
            NonZeroU16::try_from(expected_port).expect("valid"),
            proxy_port,
        );
        assert_matches!(proxy_certs, RootCertificates::Native);
    }

    #[test_case("org.signal.tls://UNENCRYPTED_FOR_TESTING@proxy.example", Host::Domain("proxy.example"), 80; "UNENCRYPTED_FOR_TESTING")]
    fn parse_proxy_signal_tcp(input: &str, expected_host: Host<&str>, expected_port: u16) {
        let TcpProxy {
            proxy_host,
            proxy_port,
        } = assert_matches!(
            ConnectionProxyConfig::from_url(input),
            Ok(ConnectionProxyConfig::Tcp(tcp)) => tcp
        );
        assert_eq!(expected_host, proxy_host.as_deref());
        assert_eq!(
            NonZeroU16::try_from(expected_port).expect("valid"),
            proxy_port,
        );
    }

    #[test_case("http://proxy.example", Host::Domain("proxy.example"), 80, None; "simple")]
    #[test_case("https://proxy.example", Host::Domain("proxy.example"), 443, None; "simple https")]
    #[test_case("http://proxy.example:4433", Host::Domain("proxy.example"), 4433, None; "with port")]
    #[test_case("https://proxy.example:4433", Host::Domain("proxy.example"), 4433, None; "with port https")]
    #[test_case("http://user@proxy.example", Host::Domain("proxy.example"), 80, Some(("user", "")); "username")]
    #[test_case("http://user:pass@proxy.example", Host::Domain("proxy.example"), 80, Some(("user", "pass")); "username + pw")]
    #[test_case("http://127.0.0.1", ip_addr!("127.0.0.1"), 80, None; "IPv4")]
    #[test_case("http://127.0.0.1:4433", ip_addr!("127.0.0.1"), 4433, None; "IPv4 with port")]
    #[test_case("http://[::1]", ip_addr!("::1"), 80, None; "bracketed IPv6")]
    fn parse_proxy_signal_http(
        input: &str,
        expected_host: impl Into<Host<&'static str>>,
        expected_port: u16,
        expected_auth: Option<(&str, &str)>,
    ) {
        let HttpProxy {
            proxy_host,
            proxy_port,
            proxy_tls,
            proxy_authorization,
            resolve_hostname_locally,
        } = assert_matches!(
            ConnectionProxyConfig::from_url(input),
            Ok(ConnectionProxyConfig::Http(http)) => http
        );
        assert_eq!(expected_host.into(), proxy_host.as_deref());
        assert_eq!(
            NonZeroU16::try_from(expected_port).expect("valid"),
            proxy_port,
        );
        // This is cheating a bit, but it's simpler than adding another "expected" argument.
        if input.starts_with("http:") {
            assert_matches!(proxy_tls, None);
        } else {
            assert_matches!(proxy_tls, Some(RootCertificates::Native));
        }
        assert_eq!(
            expected_auth,
            proxy_authorization
                .as_ref()
                .map(|auth| (auth.username.as_str(), auth.password.as_str())),
        );
        assert!(
            resolve_hostname_locally,
            "this endpoint never produces a config that defers to the proxy"
        );
    }

    #[test_case("socks4://proxy.example", Host::Domain("proxy.example"), 1080, None; "simple")]
    #[test_case("socks4a://proxy.example", Host::Domain("proxy.example"), 1080, None; "simple with socks4a")]
    #[test_case("socks4://proxy.example:4433", Host::Domain("proxy.example"), 4433, None; "with port")]
    #[test_case("socks4://user@proxy.example", Host::Domain("proxy.example"), 1080, Some("user"); "username")]
    #[test_case("socks4://127.0.0.1", ip_addr!("127.0.0.1"), 1080, None; "IPv4")]
    #[test_case("socks4://127.0.0.1:4433", ip_addr!("127.0.0.1"), 4433, None; "IPv4 with port")]
    #[test_case("socks4://[::1]", ip_addr!("::1"), 1080, None; "bracketed IPv6")]
    fn parse_proxy_signal_socks4(
        input: &str,
        expected_host: impl Into<Host<&'static str>>,
        expected_port: u16,
        expected_auth: Option<&str>,
    ) {
        let SocksProxy {
            proxy_host,
            proxy_port,
            protocol,
            resolve_hostname_locally,
        } = assert_matches!(
            ConnectionProxyConfig::from_url(input),
            Ok(ConnectionProxyConfig::Socks(socks)) => socks
        );
        assert_eq!(expected_host.into(), proxy_host.as_deref());
        assert_eq!(
            NonZeroU16::try_from(expected_port).expect("valid"),
            proxy_port,
        );
        let user = assert_matches!(protocol, socks::Protocol::Socks4 { user_id } => user_id);
        assert_eq!(expected_auth, user.as_deref());
        // This is cheating a bit, but it's simpler than adding another "expected" argument.
        assert_eq!(input.starts_with("socks4a:"), !resolve_hostname_locally);
    }

    #[test_case("socks://proxy.example", Host::Domain("proxy.example"), 1080, None; "simple")]
    #[test_case("socks5://proxy.example", Host::Domain("proxy.example"), 1080, None; "simple with socks5")]
    #[test_case("socks5h://proxy.example", Host::Domain("proxy.example"), 1080, None; "simple with socks5h")]
    #[test_case("socks://proxy.example:4433", Host::Domain("proxy.example"), 4433, None; "with port")]
    #[test_case("socks://user@proxy.example", Host::Domain("proxy.example"), 1080, Some(("user", "")); "username")]
    #[test_case("socks://user:pass@proxy.example", Host::Domain("proxy.example"), 1080, Some(("user", "pass")); "username + pw")]
    #[test_case("socks5h://user:pass@proxy.example:4433", Host::Domain("proxy.example"), 4433, Some(("user", "pass")); "everything with socks5h")]
    #[test_case("socks://127.0.0.1", ip_addr!("127.0.0.1"), 1080, None; "IPv4")]
    #[test_case("socks://127.0.0.1:4433", ip_addr!("127.0.0.1"), 4433, None; "IPv4 with port")]
    #[test_case("socks://[::1]", ip_addr!("::1"), 1080, None; "bracketed IPv6")]
    fn parse_proxy_signal_socks5(
        input: &str,
        expected_host: impl Into<Host<&'static str>>,
        expected_port: u16,
        expected_auth: Option<(&str, &str)>,
    ) {
        let SocksProxy {
            proxy_host,
            proxy_port,
            protocol,
            resolve_hostname_locally,
        } = assert_matches!(
            ConnectionProxyConfig::from_url(input),
            Ok(ConnectionProxyConfig::Socks(socks)) => socks
        );
        assert_eq!(expected_host.into(), proxy_host.as_deref());
        assert_eq!(
            NonZeroU16::try_from(expected_port).expect("valid"),
            proxy_port,
        );
        let auth =
            assert_matches!(protocol, socks::Protocol::Socks5 { username_password: auth } => auth);
        assert_eq!(
            expected_auth,
            auth.as_ref().map(|auth| (auth.0.as_str(), auth.1.as_str())),
        );
        // This is cheating a bit, but it's simpler than adding another "expected" argument.
        assert_eq!(input.starts_with("socks5h:"), !resolve_hostname_locally);
    }

    #[test_case("" => matches ProxyUrlError::InvalidUrl(_))]
    #[test_case(":-)" => matches ProxyUrlError::InvalidUrl(_); "random punctuation")]
    #[test_case("garbage://proxy.example" => matches ProxyUrlError::UnsupportedScheme(scheme) if scheme == "garbage")]
    #[test_case("socks://" => matches ProxyUrlError::InvalidUrl(url::ParseError::EmptyHost))]
    #[test_case("socks:proxy.example" => matches ProxyUrlError::InvalidUrl(url::ParseError::EmptyHost))]
    #[test_case("socks://proxy.example:0" => matches ProxyUrlError::InvalidUrl(url::ParseError::InvalidPort))]
    #[test_case("socks://proxy.example:99999" => matches ProxyUrlError::InvalidUrl(url::ParseError::InvalidPort))]
    #[test_case("socks:///" => matches ProxyUrlError::InvalidUrl(url::ParseError::EmptyHost); "extra slash")]
    #[test_case("socks:///proxy.example" => matches ProxyUrlError::InvalidUrl(url::ParseError::EmptyHost); "extra slash with host")]
    #[test_case("socks://proxy.example/path-for-some-reason" => matches ProxyUrlError::UnexpectedPath)]
    #[test_case("socks://proxy.example/?query-for-some-reason" => matches ProxyUrlError::UnexpectedQuery)]
    #[test_case("socks://proxy.example/#fragment-for-some-reason" => matches ProxyUrlError::UnexpectedFragment)]
    #[test_case("org.signal.tls://user@proxy.example" => matches ProxyUrlError::SchemeDoesNotSupportUsernames(SIGNAL_TLS_PROXY_SCHEME))]
    #[test_case("socks4://user:pass@proxy.example" => matches ProxyUrlError::SchemeDoesNotSupportPasswords("socks4"))]
    #[test_case("socks://::1" => matches ProxyUrlError::InvalidUrl(_); "naively prefixing an IPv6 address with most schemes doesn't work")]
    fn parse_proxy_invalid(input: &str) -> ProxyUrlError {
        ConnectionProxyConfig::from_url(input).expect_err("invalid input")
    }
}
