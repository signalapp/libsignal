//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::str::FromStr;
use std::string::ToString;
use std::sync::Arc;

use ::http::uri::PathAndQuery;
use ::http::Uri;
use boring::ssl::{SslConnector, SslConnectorBuilder, SslMethod};
use tokio::net::TcpStream;
use tokio_boring::SslStream;

use crate::infra::certs::RootCertificates;
use crate::infra::dns::DnsResolver;
use crate::infra::errors::NetError;

pub mod certs;
pub mod connection_manager;
pub mod dns;
pub mod errors;
pub(crate) mod http;
pub(crate) mod reconnect;
pub(crate) mod tokio_executor;
pub(crate) mod tokio_io;
pub(crate) mod ws;

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
/// only be apllied to the initial connection upgrade request).
#[derive(Clone, Debug)]
pub struct ConnectionParams {
    pub sni: Arc<str>,
    pub host: Arc<str>,
    pub port: u16,
    pub http_request_decorator: HttpRequestDecoratorSeq,
    pub certs: RootCertificates,
    pub dns_resolver: DnsResolver,
}

impl ConnectionParams {
    #[cfg(test)]
    fn new(
        sni: &str,
        host: &str,
        port: u16,
        http_request_decorator: HttpRequestDecoratorSeq,
        certs: RootCertificates,
        dns_resolver: DnsResolver,
    ) -> Self {
        Self {
            sni: Arc::from(sni),
            host: Arc::from(host),
            port,
            http_request_decorator,
            certs,
            dns_resolver,
        }
    }

    pub fn with_decorator(mut self, decorator: HttpRequestDecorator) -> Self {
        let HttpRequestDecoratorSeq(decorators) = &mut self.http_request_decorator;
        decorators.push(decorator);
        self
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

pub(crate) async fn connect_ssl(
    connection_params: &ConnectionParams,
    alpn: &[u8],
) -> Result<SslStream<TcpStream>, NetError> {
    let tcp_stream = connect_tcp(
        &connection_params.dns_resolver,
        &connection_params.sni,
        connection_params.port,
    )
    .await?;

    let ssl_config = client_ssl_connector_builder(connection_params.certs.clone(), alpn)?
        .build()
        .configure()?;

    let ssl_stream = tokio_boring::connect(ssl_config, &connection_params.sni, tcp_stream)
        .await
        .map_err(|_| NetError::SslFailedHandshake)?;

    Ok(ssl_stream)
}

pub(crate) async fn connect_tcp(
    dns_resolver: &DnsResolver,
    host: &str,
    port: u16,
) -> Result<TcpStream, NetError> {
    let dns_lookup = dns_resolver
        .lookup_ip(host)
        .await
        .map_err(|_| NetError::DnsError)?;
    for ip in dns_lookup.iter() {
        match TcpStream::connect((*ip, port)).await {
            Ok(tcp_stream) => return Ok(tcp_stream),
            Err(_) => continue,
        }
    }
    Err(NetError::TcpConnectionFailed)
}

pub(crate) fn client_ssl_connector_builder(
    certs: RootCertificates,
    alpn: &[u8],
) -> Result<SslConnectorBuilder, NetError> {
    let mut ssl = SslConnector::builder(SslMethod::tls_client())?;
    ssl.set_verify_cert_store(certs.try_into()?)?;
    ssl.set_alpn_protos(alpn)?;
    Ok(ssl)
}

#[cfg(test)]
pub(crate) mod test {
    use hyper::Request;

    use crate::infra::HttpRequestDecorator;
    use crate::utils::basic_authorization;

    pub(crate) mod shared {
        use crate::infra::errors::LogSafeDisplay;
        use displaydoc::Display;
        use std::time::Duration;

        #[derive(Debug, Display)]
        pub(crate) enum TestError {
            /// expected error
            Expected,
            /// unexpected error
            Unexpected,
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
