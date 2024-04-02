//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::num::NonZeroU16;
use std::str::FromStr;
use std::string::ToString;
use std::sync::Arc;
use std::time::Duration;

use crate::env::{WS_KEEP_ALIVE_INTERVAL, WS_MAX_IDLE_TIME};
use ::http::uri::PathAndQuery;
use ::http::Uri;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use url::Host;

use crate::infra::certs::RootCertificates;
use crate::infra::connection_manager::{
    MultiRouteConnectionManager, SingleRouteThrottlingConnectionManager,
};
use crate::infra::errors::TransportConnectError;
use crate::infra::ws::WebSocketConfig;

pub mod certs;
pub mod connection_manager;
pub mod dns;
pub mod errors;
pub(crate) mod reconnect;
pub mod tcp_ssl;
pub mod ws;

#[derive(Copy, Clone, Debug)]
#[repr(u8)]
pub enum IpType {
    Unknown = 0,
    V4 = 1,
    V6 = 2,
}

impl IpType {
    pub(crate) fn from_host(host: &Host) -> Self {
        match host {
            Host::Domain(_) => IpType::Unknown,
            Host::Ipv4(_) => IpType::V4,
            Host::Ipv6(_) => IpType::V6,
        }
    }
}

/// A collection of commonly used decorators for HTTP requests.
#[derive(Clone, Debug)]
pub enum HttpRequestDecorator {
    /// Adds the following header to the request:
    /// ```text
    /// Authorization: Basic base64(<username>:<password>)
    /// ```
    HeaderAuth(String),
    /// Prefixes the path portion of the request with the given string.
    PathPrefix(&'static str),
    /// Applies generic decoration logic.
    Generic(fn(hyper::http::request::Builder) -> hyper::http::request::Builder),
}

#[derive(Clone, Debug, Default)]
pub struct HttpRequestDecoratorSeq(Vec<HttpRequestDecorator>);

impl From<HttpRequestDecorator> for HttpRequestDecoratorSeq {
    fn from(value: HttpRequestDecorator) -> Self {
        Self(vec![value])
    }
}

/// Contains all information required to establish an HTTP connection to the remote endpoint:
/// - `sni` value to be used in TLS,
/// - `host` value to be used for DNS resolution an in the HTTP requests headers,
/// - `port` to connect to,
/// - `http_request_decorator`, a [HttpRequestDecorator] to apply to all HTTP requests,
/// - `certs`, [RootCertificates] representing trusted certificates,
/// - `dns_resolver`, a [DnsResolver] to use when resolving DNS.
/// This is also applicable to WebSocket connections (in this case, `http_request_decorator` will
/// only be applied to the initial connection upgrade request).
#[derive(Clone, Debug)]
pub struct ConnectionParams {
    pub route_type: &'static str,
    pub sni: Arc<str>,
    pub host: Arc<str>,
    pub port: NonZeroU16,
    pub http_request_decorator: HttpRequestDecoratorSeq,
    pub certs: RootCertificates,
}

impl ConnectionParams {
    pub fn new(
        route_type: &'static str,
        sni: &str,
        host: &str,
        port: NonZeroU16,
        http_request_decorator: HttpRequestDecoratorSeq,
        certs: RootCertificates,
    ) -> Self {
        Self {
            route_type,
            sni: Arc::from(sni),
            host: Arc::from(host),
            port,
            http_request_decorator,
            certs,
        }
    }

    pub fn with_decorator(mut self, decorator: HttpRequestDecorator) -> Self {
        let HttpRequestDecoratorSeq(decorators) = &mut self.http_request_decorator;
        decorators.push(decorator);
        self
    }

    pub fn with_certs(mut self, certs: RootCertificates) -> Self {
        self.certs = certs;
        self
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ConnectionInfo {
    /// Type of the connection, e.g. direct or via proxy
    pub route_type: &'static str,

    /// The source of the DNS data, e.g. lookup or static fallback
    pub dns_source: DnsSource,

    /// Address that was used to establish the connection
    ///
    /// If IP information is available, it's recommended to use [Host::Ipv4] or [Host::Ipv6]
    /// and only use [Host::Domain] as a fallback.
    pub address: Host,
}

/// Source for the result of a hostname lookup.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum DnsSource {
    /// The result came from performing a DNS query.
    Lookup,
    /// The result was resolved from a preconfigured static entry.
    Static,
    /// Test-only value
    #[cfg(test)]
    Test,
}

impl ConnectionInfo {
    pub fn description(&self) -> String {
        format!(
            "route={};dns_source={};ip_type={:?}",
            self.route_type,
            self.dns_source,
            IpType::from_host(&self.address)
        )
    }
}

impl HttpRequestDecoratorSeq {
    pub fn decorate_request(
        &self,
        request_builder: hyper::http::request::Builder,
    ) -> hyper::http::request::Builder {
        self.0
            .iter()
            .fold(request_builder, |rb, dec| dec.decorate_request(rb))
    }
}

impl HttpRequestDecorator {
    fn decorate_request(
        &self,
        request_builder: hyper::http::request::Builder,
    ) -> hyper::http::request::Builder {
        match self {
            Self::Generic(decorator) => decorator(request_builder),
            Self::HeaderAuth(auth) => request_builder.header(::http::header::AUTHORIZATION, auth),
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

pub struct StreamAndInfo<T>(T, ConnectionInfo);

impl<T> StreamAndInfo<T> {
    fn map_stream<U>(self, f: impl FnOnce(T) -> U) -> StreamAndInfo<U> {
        StreamAndInfo(f(self.0), self.1)
    }
}

pub trait AsyncDuplexStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncDuplexStream for S {}

#[async_trait]
pub trait TransportConnector: Clone + Send + Sync {
    type Stream: AsyncDuplexStream + 'static;

    async fn connect(
        &self,
        connection_params: &ConnectionParams,
        alpn: Alpn,
    ) -> Result<StreamAndInfo<Self::Stream>, TransportConnectError>;
}

/// A single ALPN list entry.
///
/// Implements `AsRef<[u8]>` as the length-delimited wire form.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Alpn {
    Http1_1,
}

impl AsRef<[u8]> for Alpn {
    fn as_ref(&self) -> &[u8] {
        match self {
            Alpn::Http1_1 => b"\x08http/1.1",
        }
    }
}

pub struct EndpointConnection<C> {
    pub manager: C,
    pub config: WebSocketConfig,
}

impl EndpointConnection<MultiRouteConnectionManager> {
    pub fn new_multi(
        connection_params: impl IntoIterator<Item = ConnectionParams>,
        connect_timeout: Duration,
        config: WebSocketConfig,
    ) -> Self {
        Self {
            manager: MultiRouteConnectionManager::new(
                connection_params
                    .into_iter()
                    .map(|params| {
                        SingleRouteThrottlingConnectionManager::new(params, connect_timeout)
                    })
                    .collect(),
                connect_timeout,
            ),
            config,
        }
    }
}

pub fn make_ws_config(
    websocket_endpoint: PathAndQuery,
    connect_timeout: Duration,
) -> WebSocketConfig {
    WebSocketConfig {
        ws_config: tungstenite::protocol::WebSocketConfig::default(),
        endpoint: websocket_endpoint,
        max_connection_time: connect_timeout,
        keep_alive_interval: WS_KEEP_ALIVE_INTERVAL,
        max_idle_time: WS_MAX_IDLE_TIME,
    }
}

#[cfg(test)]
pub(crate) mod test {
    use hyper::Request;

    use crate::infra::HttpRequestDecorator;
    use crate::utils::basic_authorization;

    pub(crate) mod shared {
        use std::fmt::Debug;
        use std::io;
        use std::sync::Arc;
        use std::time::Duration;

        use async_trait::async_trait;
        use derive_where::derive_where;
        use displaydoc::Display;
        use tokio::io::DuplexStream;
        use warp::{Filter, Reply};

        use crate::infra::connection_manager::ConnectionManager;
        use crate::infra::errors::{LogSafeDisplay, TransportConnectError};
        use crate::infra::reconnect::{
            ServiceConnector, ServiceInitializer, ServiceState, ServiceStatus,
        };
        use crate::infra::{
            Alpn, ConnectionInfo, ConnectionParams, DnsSource, StreamAndInfo, TransportConnector,
        };

        #[test]
        fn connection_info_description() {
            let connection_info = ConnectionInfo {
                address: url::Host::Domain("test.signal.org".to_string()),
                dns_source: DnsSource::Lookup,
                route_type: "test-route-type",
            };

            assert_eq!(
                connection_info.description(),
                "route=test-route-type;dns_source=lookup;ip_type=Unknown"
            );
        }

        #[derive(Debug, Display)]
        pub(crate) enum TestError {
            /// expected error
            Expected,
            /// unexpected error
            Unexpected(&'static str),
        }

        impl LogSafeDisplay for TestError {}

        // the choice of the constant value is dictated by a vague notion of being
        // "not too many, but also not just once or twice"
        pub(crate) const FEW_ATTEMPTS: u16 = 3;

        pub(crate) const MANY_ATTEMPTS: u16 = 1000;

        pub(crate) const TIMEOUT_DURATION: Duration = Duration::from_millis(100);

        pub(crate) const NORMAL_CONNECTION_TIME: Duration = Duration::from_millis(20);

        pub(crate) const LONG_CONNECTION_TIME: Duration = Duration::from_secs(10);

        // we need to advance time in tests by some value not to run into the scenario
        // of attempts starting at the same time, but also by not too much so that we
        // don't step over the cool down time
        pub(crate) const TIME_ADVANCE_VALUE: Duration = Duration::from_millis(5);

        #[derive(Clone)]
        pub(crate) struct InMemoryWarpConnector<F> {
            filter: F,
        }

        impl<F> InMemoryWarpConnector<F> {
            pub fn new(filter: F) -> Self {
                Self { filter }
            }
        }

        #[async_trait]
        impl<F> TransportConnector for InMemoryWarpConnector<F>
        where
            F: Filter + Clone + Send + Sync + 'static,
            F::Extract: Reply,
        {
            type Stream = DuplexStream;

            async fn connect(
                &self,
                connection_params: &ConnectionParams,
                _alpn: Alpn,
            ) -> Result<StreamAndInfo<Self::Stream>, TransportConnectError> {
                let (client, server) = tokio::io::duplex(1024);
                let routes = self.filter.clone();
                tokio::spawn(async {
                    let one_element_iter =
                        futures_util::stream::iter(vec![Ok::<DuplexStream, io::Error>(server)]);
                    warp::serve(routes).run_incoming(one_element_iter).await;
                });
                Ok(StreamAndInfo(
                    client,
                    ConnectionInfo {
                        route_type: "test",
                        dns_source: DnsSource::Test,
                        address: url::Host::Domain(connection_params.host.to_string()),
                    },
                ))
            }
        }

        #[derive_where(Clone)]
        pub(crate) struct NoReconnectService<C: ServiceConnector> {
            pub(crate) inner: Arc<ServiceState<C::Service, C::ConnectError, C::StartError>>,
        }

        impl<C> NoReconnectService<C>
        where
            C: ServiceConnector + Send + Sync + 'static,
            C::Service: Clone + Send + Sync + 'static,
            C::Channel: Send + Sync,
            C::ConnectError: Send + Sync + Debug + LogSafeDisplay,
        {
            pub(crate) async fn start<M>(service_connector: C, connection_manager: M) -> Self
            where
                M: ConnectionManager + 'static,
            {
                let status = ServiceInitializer::new(service_connector, connection_manager)
                    .connect()
                    .await;
                Self {
                    inner: Arc::new(status),
                }
            }

            pub(crate) fn service_status(&self) -> Option<&ServiceStatus<C::StartError>> {
                match &*self.inner {
                    ServiceState::Active(_, status) => Some(status),
                    _ => None,
                }
            }
        }
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
            assert_eq!(expected_path, parts.uri.path(), "for input [{}]", input)
        }
    }

    #[test]
    fn test_header_auth_decorator() {
        let expected = "Basic dXNybm06cHNzd2Q=";
        let builder = Request::get("https://chat.signal.org/");
        let builder = HttpRequestDecorator::HeaderAuth(basic_authorization("usrnm", "psswd"))
            .decorate_request(builder);
        let (parts, _) = builder.body(()).unwrap().into_parts();
        assert_eq!(
            expected,
            parts.headers.get(http::header::AUTHORIZATION).unwrap()
        );
    }
}
