//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::net::IpAddr;
use std::num::NonZeroU16;
use std::str::FromStr;
use std::string::ToString;
use std::sync::Arc;

use ::http::uri::PathAndQuery;
use ::http::Uri;
use http::{HeaderMap, HeaderName, HeaderValue};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::certs::RootCertificates;
use crate::errors::{LogSafeDisplay, RetryLater};
use crate::host::Host;
use crate::timeouts::{WS_KEEP_ALIVE_INTERVAL, WS_MAX_IDLE_INTERVAL};

pub mod certs;
pub mod dns;
pub mod errors;
pub mod host;
pub mod http_client;
pub mod noise;
pub mod route;
pub mod tcp_ssl;
pub mod timeouts;
pub mod utils;
pub mod ws;
pub mod ws2;

#[derive(Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
#[repr(u8)]
pub enum IpType {
    V4 = 1,
    V6 = 2,
}

impl IpType {
    pub fn from_host<S>(host: &Host<S>) -> Option<Self> {
        match host {
            Host::Domain(_) => None,
            Host::Ip(IpAddr::V4(_)) => Some(IpType::V4),
            Host::Ip(IpAddr::V6(_)) => Some(IpType::V6),
        }
    }
}

impl From<&IpAddr> for IpType {
    fn from(value: &IpAddr) -> Self {
        match value {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }
}

impl LogSafeDisplay for IpType {}
impl std::fmt::Display for IpType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// Whether or not to enable domain fronting.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub enum EnableDomainFronting {
    No,
    OneDomainPerProxy,
    AllDomains,
}

/// Whether to enforce minimum TLS version requirements.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EnforceMinimumTls {
    Yes,
    No,
}

/// A collection of commonly used decorators for HTTP requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HttpRequestDecorator {
    /// Adds a collection of headers to the request
    Headers(http::header::HeaderMap),
    /// Prefixes the path portion of the request with the given string.
    PathPrefix(&'static str),
    /// Applies generic decoration logic.
    Generic(fn(http::request::Builder) -> http::request::Builder),
}

#[derive(Clone, Debug, Default)]
pub struct HttpRequestDecoratorSeq(Vec<HttpRequestDecorator>);

impl From<HttpRequestDecorator> for HttpRequestDecoratorSeq {
    fn from(value: HttpRequestDecorator) -> Self {
        Self(vec![value])
    }
}

impl HttpRequestDecoratorSeq {
    pub fn add(&mut self, decorator: HttpRequestDecorator) {
        self.0.push(decorator)
    }
}

/// The fully general version of [`AsStaticHttpHeader`], where the name of the header may depend on the
/// value.
pub trait AsHttpHeader {
    fn as_header(&self) -> (HeaderName, HeaderValue);
}

/// A common form for values that are passed in HTTP headers.
///
/// If the header name depends on the value, implement [`AsHttpHeader`] instead.
pub trait AsStaticHttpHeader: AsHttpHeader {
    const HEADER_NAME: HeaderName;

    fn header_value(&self) -> HeaderValue;
}

impl<T: AsStaticHttpHeader> AsHttpHeader for T {
    fn as_header(&self) -> (HeaderName, HeaderValue) {
        (Self::HEADER_NAME, self.header_value())
    }
}

impl<T: AsHttpHeader> From<&'_ T> for HttpRequestDecorator {
    fn from(value: &'_ T) -> Self {
        let (name, value) = value.as_header();
        HttpRequestDecorator::header(name, value)
    }
}

/// Contains all information required to establish an HTTP connection to a remote endpoint.
///
/// For WebSocket connections, `http_request_decorator` will only be applied to the initial
/// connection upgrade request.
#[derive(Clone, Debug)]
pub struct ConnectionParams {
    /// High-level classification of the route (mostly for logging)
    pub route_type: RouteType,
    /// Host name used in the HTTP headers.
    pub http_host: Arc<str>,
    /// Applied to all HTTP requests.
    pub http_request_decorator: HttpRequestDecoratorSeq,
    /// If present, differentiates HTTP responses that actually come from the remote endpoint from
    /// those produced by an intermediate server.
    pub connection_confirmation_header: Option<HeaderName>,
    /// Transport-level connection configuration
    pub transport: TransportConnectionParams,
}

impl ConnectionParams {
    pub fn with_decorator(mut self, decorator: HttpRequestDecorator) -> Self {
        let HttpRequestDecoratorSeq(decorators) = &mut self.http_request_decorator;
        decorators.push(decorator);
        self
    }

    pub fn with_confirmation_header(mut self, header: HeaderName) -> Self {
        self.connection_confirmation_header = Some(header);
        self
    }
}

/// Contains all information required to establish a TLS connection to a remote endpoint.
#[derive(Clone, Debug)]
pub struct TransportConnectionParams {
    /// Host name to be used in the TLS handshake SNI field.
    pub sni: Arc<str>,
    /// Host name used for DNS resolution.
    pub tcp_host: Host<Arc<str>>,
    /// Port to connect to.
    pub port: NonZeroU16,
    /// Trusted certificates for this connection.
    pub certs: RootCertificates,
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ServiceConnectionInfo {
    /// Type of the connection, e.g. direct or via proxy
    pub route_type: RouteType,

    /// The source of the DNS data, e.g. lookup or static fallback
    pub dns_source: DnsSource,

    /// Address that was used to establish the connection
    ///
    /// If IP information is available, it's recommended to use [Host::Ip] and
    /// only use [Host::Domain] as a fallback.
    pub address: Host<Arc<str>>,
}

/// Information about a currently- or previously-established connection to a
/// remote host.
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct TransportInfo {
    /// The IP address version over which the connection is established.
    pub ip_version: IpType,

    /// The local port number for the connection.
    pub local_port: u16,
}

/// An established connection.
pub trait Connection {
    /// Returns transport-level information about the connection.
    fn transport_info(&self) -> TransportInfo;
}

/// Source for the result of a hostname lookup.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum DnsSource {
    /// The result was returned from the cache
    Cache,
    /// The result came from performing a plaintext DNS query over UDP.
    UdpLookup,
    /// The result came from performing a DNS-over-HTTPS query.
    DnsOverHttpsLookup,
    /// The result came from performing a DNS query using a system resolver.
    SystemLookup,
    /// The result was resolved from a preconfigured static entry.
    Static,
    /// The result came from delegating to a remote resource.
    Delegated,
    /// Test-only value
    #[cfg(any(test, feature = "test-util"))]
    Test,
}

/// Type of the route used for the connection.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, strum::Display, strum::IntoStaticStr)]
#[strum(serialize_all = "lowercase")]
pub enum RouteType {
    /// Direct connection to the service.
    Direct,
    /// Connection over the Google proxy
    ProxyF,
    /// Connection over the Fastly proxy
    ProxyG,
    /// Connection over a custom TLS proxy
    TlsProxy,
    /// Connection over a SOCKS proxy
    SocksProxy,
    /// Test-only value
    #[cfg(any(test, feature = "test-util"))]
    Test,
}

impl ServiceConnectionInfo {
    pub fn description(&self) -> String {
        let ip_type = match IpType::from_host(&self.address) {
            Some(IpType::V4) => "V4",
            Some(IpType::V6) => "V6",
            None => "Unknown",
        };
        format!(
            "route={};dns_source={};ip_type={}",
            self.route_type, self.dns_source, ip_type
        )
    }
}

impl HttpRequestDecoratorSeq {
    pub fn decorate_request(
        &self,
        request_builder: http::request::Builder,
    ) -> http::request::Builder {
        self.0
            .iter()
            .fold(request_builder, |rb, dec| dec.decorate_request(rb))
    }
}

impl HttpRequestDecorator {
    /// Convenience constructor for [`HttpRequestDecorator::Headers`] with a map
    /// with one entry.
    pub fn header(name: HeaderName, value: HeaderValue) -> Self {
        Self::Headers(HeaderMap::from_iter([(name, value)]))
    }

    fn decorate_request(&self, request_builder: http::request::Builder) -> http::request::Builder {
        match self {
            Self::Generic(decorator) => decorator(request_builder),
            Self::Headers(header_map) => header_map
                .into_iter()
                .fold(request_builder, |builder, (name, value)| {
                    builder.header(name, value)
                }),
            Self::PathPrefix(prefix) => {
                let uri = request_builder.uri_ref().expect("request has URI set");
                let mut parts = (*uri).clone().into_parts();
                let decorated_pq = match parts.path_and_query {
                    Some(pq) => format!("{}{}", prefix, pq.as_str()),
                    None => prefix.to_string(),
                };
                parts.path_and_query = Some(
                    PathAndQuery::from_str(decorated_pq.as_str()).expect("valid path and query"),
                );
                request_builder.uri(Uri::from_parts(parts).expect("valid uri"))
            }
        }
    }
}

pub trait AsyncDuplexStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncDuplexStream for S {}

/// A single ALPN list entry.
///
/// Implements `AsRef<[u8]>` as the length-delimited wire form.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Alpn {
    Http1_1,
    Http2,
}

impl AsRef<[u8]> for Alpn {
    fn as_ref(&self) -> &[u8] {
        match self {
            Alpn::Http1_1 => b"\x08http/1.1",
            Alpn::Http2 => b"\x02h2",
        }
    }
}

pub const RECOMMENDED_WS2_CONFIG: ws2::Config = {
    ws2::Config {
        local_idle_timeout: WS_KEEP_ALIVE_INTERVAL,
        remote_idle_ping_timeout: WS_KEEP_ALIVE_INTERVAL,
        remote_idle_disconnect_timeout: WS_MAX_IDLE_INTERVAL,
    }
};

/// Extracts and parses the `Retry-After` header.
///
/// Does not support the "http-date" form of the header.
pub fn extract_retry_later(headers: &http::header::HeaderMap) -> Option<RetryLater> {
    let retry_after_seconds = headers
        .get(RetryLater::HEADER_NAME)?
        .to_str()
        .ok()?
        .parse()
        .ok()?;
    Some(RetryLater {
        retry_after_seconds,
    })
}

#[cfg(any(test, feature = "test-util"))]
pub mod testutil {
    use std::fmt::Debug;
    use std::io::Error as IoError;
    use std::pin::Pin;
    use std::sync::LazyLock;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use displaydoc::Display;
    use futures_util::stream::FusedStream;
    use futures_util::{Sink, SinkExt as _, Stream};
    use tokio_util::sync::PollSender;

    use crate::errors::LogSafeDisplay;
    use crate::utils::NetworkChangeEvent;

    #[derive(Debug, Display)]
    pub enum TestError {
        /// expected error
        Expected,
        /// unexpected error
        Unexpected(&'static str),
    }

    impl LogSafeDisplay for TestError {}

    // This could be Copy, but we don't want to rely on *all* errors being Copy, or only test
    // that case.

    // the choice of the constant value is dictated by a vague notion of being
    // "not too many, but also not just once or twice"

    pub const TIMEOUT_DURATION: Duration = Duration::from_millis(1000);

    // we need to advance time in tests by some value not to run into the scenario
    // of attempts starting at the same time, but also by not too much so that we
    // don't step over the cool down time

    pub fn no_network_change_events() -> NetworkChangeEvent {
        static SENDER_THAT_NEVER_SENDS: LazyLock<tokio::sync::watch::Sender<()>> =
            LazyLock::new(Default::default);
        SENDER_THAT_NEVER_SENDS.subscribe()
    }

    /// Trivial [`Sink`] and [`Stream`] implementation over a pair of buffered channels.
    pub struct TestStream<T, E> {
        rx: tokio::sync::mpsc::Receiver<Result<T, E>>,
        tx: PollSender<Result<T, E>>,
    }

    impl<T: Send, E: Send> TestStream<T, E> {
        pub fn new_pair(channel_size: usize) -> (Self, Self) {
            let [lch, rch] = [(); 2].map(|()| tokio::sync::mpsc::channel(channel_size));
            let l = Self {
                rx: lch.1,
                tx: PollSender::new(rch.0),
            };
            let r = Self {
                rx: rch.1,
                tx: PollSender::new(lch.0),
            };
            (l, r)
        }

        pub async fn send_error(&mut self, error: E) -> Result<(), Option<E>> {
            self.tx.send(Err(error)).await.map_err(|e| {
                e.into_inner().map(|r| match r {
                    Ok(_) => unreachable!("sent item was an error"),
                    Err(e) => e,
                })
            })
        }
        pub fn rx_is_closed(&self) -> bool {
            self.rx.is_closed()
        }
    }

    impl<T: Send, E: Send> Stream for TestStream<T, E> {
        type Item = Result<T, E>;

        fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.get_mut().rx.poll_recv(cx)
        }
    }

    impl<T: Send, E: Send> FusedStream for TestStream<T, E> {
        fn is_terminated(&self) -> bool {
            self.rx.is_closed() && self.rx.is_empty()
        }
    }

    impl<T: Send, E: Send + From<IoError>> Sink<T> for TestStream<T, E> {
        type Error = E;

        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.get_mut()
                .tx
                .poll_ready_unpin(cx)
                .map_err(|_| IoError::other("poll_reserve for send failed").into())
        }

        fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
            self.get_mut()
                .tx
                .start_send_unpin(Ok(item))
                .map_err(|_| IoError::other("send failed").into())
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.get_mut()
                .tx
                .poll_flush_unpin(cx)
                .map_err(|_| IoError::other("flush failed").into())
        }

        fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            self.get_mut()
                .tx
                .poll_close_unpin(cx)
                .map_err(|_| IoError::other("close failed").into())
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use const_str::ip_addr;
    use http::Request;

    use crate::host::Host;
    use crate::utils::basic_authorization;
    use crate::{DnsSource, HttpRequestDecorator, RouteType, ServiceConnectionInfo};

    #[test]
    fn connection_info_description() {
        let connection_info = ServiceConnectionInfo {
            address: Host::Domain("test.signal.org".into()),
            dns_source: DnsSource::SystemLookup,
            route_type: RouteType::Test,
        };

        assert_eq!(
            connection_info.description(),
            "route=test;dns_source=systemlookup;ip_type=Unknown"
        );

        assert_eq!(
            ServiceConnectionInfo {
                address: Host::Ip(ip_addr!("192.0.2.4")),
                ..connection_info
            }
            .description(),
            "route=test;dns_source=systemlookup;ip_type=V4"
        )
    }

    #[test]
    fn test_path_prefix_decorator() {
        let cases = vec![
            ("https://chat.signal.org/", "/chat/"),
            ("https://chat.signal.org/v1", "/chat/v1"),
            ("https://chat.signal.org/v1?a=b", "/chat/v1"),
            ("https://chat.signal.org/v1/endpoint", "/chat/v1/endpoint"),
        ];
        for (input, expected_path) in cases.into_iter() {
            let builder = Request::get(input);
            let builder = HttpRequestDecorator::PathPrefix("/chat").decorate_request(builder);
            let (parts, _) = builder.body(()).unwrap().into_parts();
            assert_eq!(expected_path, parts.uri.path(), "for input [{input}]")
        }
    }

    #[test]
    fn test_header_auth_decorator() {
        let expected = "Basic dXNybm06cHNzd2Q=";
        let builder = Request::get("https://chat.signal.org/");
        let builder = HttpRequestDecorator::header(
            http::header::AUTHORIZATION,
            basic_authorization("usrnm", "psswd"),
        )
        .decorate_request(builder);
        let (parts, _) = builder.body(()).unwrap().into_parts();
        assert_eq!(
            expected,
            parts.headers.get(http::header::AUTHORIZATION).unwrap()
        );
    }
}
