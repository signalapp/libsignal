//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#![warn(clippy::unwrap_used)]

use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU16;
use std::sync::Arc;

use http::{HeaderName, HeaderValue};
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
pub mod route;
pub mod stream;
pub mod tcp_ssl;
#[cfg(any(test, feature = "test-util"))]
pub mod testutil;
pub mod timeouts;
pub mod utils;
pub mod ws;

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

/// Whether to override the platform default for the Nagle algorithm via TCP_NODELAY.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum OverrideNagleAlgorithm {
    /// Explicitly disable the Nagle algorithm (enable TCP_NODELAY).
    OverrideToOff,
    /// Leave the operating system's default behavior unchanged.
    #[default]
    UseSystemDefault,
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
    /// Prefix prepended to the path of all HTTP requests.
    pub path_prefix: Option<&'static str>,
    /// If present, differentiates HTTP responses that actually come from the remote endpoint from
    /// those produced by an intermediate server.
    pub connection_confirmation_header: Option<HeaderName>,
    /// Transport-level connection configuration
    pub transport: TransportConnectionParams,
}

impl ConnectionParams {
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
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
}

impl TransportInfo {
    pub fn ip_version(&self) -> IpType {
        match self.local_addr.ip() {
            IpAddr::V4(_) => IpType::V4,
            IpAddr::V6(_) => IpType::V6,
        }
    }
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

pub trait AsyncDuplexStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncDuplexStream for S {}

/// A single ALPN list entry.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Alpn {
    Http1_1,
    Http2,
}

impl Alpn {
    pub const fn encoded(&self) -> &'static [u8] {
        self.length_prefixed()
            .split_first()
            .expect("always has a prefix to strip")
            .1
    }

    pub const fn length_prefixed(&self) -> &'static [u8] {
        match self {
            Self::Http1_1 => b"\x08http/1.1",
            Self::Http2 => b"\x02h2",
        }
    }
}

pub struct UnrecognizedAlpn;

impl TryFrom<&'_ [u8]> for Alpn {
    type Error = UnrecognizedAlpn;

    fn try_from(value: &'_ [u8]) -> Result<Self, Self::Error> {
        if value == Self::Http2.encoded() {
            return Ok(Self::Http2);
        }
        if value == Self::Http1_1.encoded() {
            return Ok(Self::Http1_1);
        }
        Err(UnrecognizedAlpn)
    }
}

pub const RECOMMENDED_WS_CONFIG: ws::Config = {
    ws::Config {
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

#[cfg(test)]
pub(crate) mod test {
    use const_str::ip_addr;

    use crate::host::Host;
    use crate::{DnsSource, RouteType, ServiceConnectionInfo};

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
}
