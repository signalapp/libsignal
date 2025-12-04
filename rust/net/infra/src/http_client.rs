//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::error::Error;
use std::marker::PhantomData;
use std::str::FromStr as _;

use bytes::Bytes;
use derive_where::derive_where;
use http::HeaderMap;
use http::response::Parts;
use http::uri::PathAndQuery;
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use static_assertions::assert_impl_all;

use crate::errors::{LogSafeDisplay, TransportConnectError};
use crate::route::{Connector, HttpRouteFragment, HttpVersion};
use crate::{AsyncDuplexStream, Connection};

#[derive(displaydoc::Display, Debug)]
pub enum HttpError {
    /// SSL handshake failed
    SslHandshakeFailed,
    /// HTTP2 handshake failed
    Http2HandshakeFailed,
    /// Failed to create HTTP request
    FailedToCreateRequest,
    /// Failed to send request or receive the response
    SendRequestError,
    /// `Content-Length` header has invalid value
    ContentLengthHeaderInvalid,
    /// Failed while reading response body with the known `Content-Length`
    FailedToReadContentOfKnownSize,
    /// Failed while reading response body with the unknown size
    FailedToReadContentOfUnknownSize,
    /// Content larger than max size configured for the client
    ResponseTooLarge,
}

/// A wrapper around hyper's [`SendRequest`](http2::SendRequest) that supports a prepended path
/// prefix and consistent host.
///
/// Created using [`Http2Connector`].
///
/// When `tower-service` is enabled, `Http2Client` can be used as a [`tower_service::Service`].
#[derive(Debug)]
#[derive_where(Clone)]
pub struct Http2Client<B> {
    service: http2::SendRequest<B>,
    authority: http::uri::Authority,
    path_prefix: Option<http::uri::PathAndQuery>,
}

impl<B: hyper::body::Body + 'static> Http2Client<B> {
    #[cfg(feature = "tower-service")]
    pub fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), hyper::Error>> {
        self.service.poll_ready(cx)
    }

    pub async fn ready(&mut self) -> Result<(), hyper::Error> {
        self.service.ready().await
    }

    pub fn send_request(
        &mut self,
        mut req: http::Request<B>,
    ) -> impl Future<Output = Result<http::Response<hyper::body::Incoming>, hyper::Error>> + 'static
    {
        let mut uri = std::mem::take(req.uri_mut()).into_parts();
        uri.authority = Some(self.authority.clone());
        uri.scheme = Some(http::uri::Scheme::HTTPS);
        if let Some(prefix) = self.path_prefix.as_ref() {
            uri.path_and_query = Some(
                http::uri::PathAndQuery::from_str(&format!(
                    "{}{}",
                    prefix,
                    uri.path_and_query.as_ref().map_or("", |path| path.as_str())
                ))
                .expect("valid path prefix"),
            );
        }
        *req.uri_mut() = http::Uri::from_parts(uri).expect("valid parts");

        self.service.send_request(req)
    }
}

#[cfg(feature = "tower-service")]
impl<B: hyper::body::Body + Send + 'static> tower_service::Service<http::Request<B>>
    for Http2Client<B>
{
    type Response = http::Response<hyper::body::Incoming>;
    type Error = hyper::Error;
    type Future = futures_util::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.poll_ready(cx)
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        Box::pin(self.send_request(req))
    }
}

/// An [Http2Client] that always makes requests all at once, as opposed to streaming either request
/// or response bodies.
///
/// Convenient for one-off or ad-hoc requests.
#[derive(Debug, Clone)]
pub struct AggregatingHttp2Client {
    service: Http2Client<Full<Bytes>>,
    max_response_size: usize,
}

impl AggregatingHttp2Client {
    pub fn new(service: Http2Client<Full<Bytes>>, max_response_size: usize) -> Self {
        Self {
            service,
            max_response_size,
        }
    }

    pub async fn send_request_aggregate_response(
        &mut self,
        path_and_query: PathAndQuery,
        method: http::Method,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<(Parts, Bytes), HttpError> {
        let mut request_builder = http::Request::builder()
            .method(method)
            .uri(http::Uri::from(path_and_query))
            .version(http::Version::HTTP_2);

        request_builder
            .headers_mut()
            // This can fail if the builder is invalid.
            .ok_or(HttpError::FailedToCreateRequest)?
            .extend(headers);

        let content_length = body.len();
        let request = request_builder
            .header(http::header::CONTENT_LENGTH, content_length)
            .body(Full::new(body))
            .map_err(|_| HttpError::FailedToCreateRequest)?;

        self.service
            .ready()
            .await
            .map_err(|_| HttpError::SendRequestError)?;
        let res = self
            .service
            .send_request(request)
            .await
            .map_err(|_| HttpError::SendRequestError)?;

        let (parts, body) = res.into_parts();

        let content_length = parts
            .headers
            .get(hyper::header::CONTENT_LENGTH)
            .map(|c| {
                c.to_str()
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or(HttpError::ContentLengthHeaderInvalid)
            })
            .transpose()?;

        let content = match content_length {
            Some(content_length) if content_length > self.max_response_size => {
                return Err(HttpError::ResponseTooLarge);
            }
            Some(content_length) => Limited::new(body, content_length)
                .collect()
                .await
                .map_err(|_| HttpError::FailedToReadContentOfKnownSize)?,
            _ => Limited::new(body, self.max_response_size)
                .collect()
                .await
                .map_err(|_| HttpError::FailedToReadContentOfUnknownSize)?,
        }
        .to_bytes();

        Ok((parts, content))
    }
}

pub struct Http2Connector<B = Full<Bytes>> {
    request_body: PhantomData<fn(B)>,
}

impl<B> Http2Connector<B> {
    // More parameters are coming soon.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            request_body: PhantomData,
        }
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum HttpConnectError {
    /// {0}
    Transport(#[from] TransportConnectError),
    /// HTTP handshake failed
    HttpHandshake,
    /// {0}
    InvalidConfig(&'static str),
}

assert_impl_all!(TransportConnectError: LogSafeDisplay);
impl LogSafeDisplay for HttpConnectError {}

/// A refinement of [`hyper::body::Body`] that supports our use of hyper's H2 connections.
pub trait H2Body:
    hyper::body::Body<Data: Send, Error: Into<Box<dyn Error + Send + Sync>>> + Send + Unpin + 'static
{
}
impl<T> H2Body for T where
    T: hyper::body::Body<Data: Send, Error: Into<Box<dyn Error + Send + Sync>>>
        + Send
        + Unpin
        + 'static
{
}

impl<B, Inner> Connector<HttpRouteFragment, Inner> for Http2Connector<B>
where
    Inner: Connection + AsyncDuplexStream + Send + 'static,
    B: H2Body,
{
    type Connection = Http2Client<B>;
    type Error = HttpConnectError;

    async fn connect_over(
        &self,
        over: Inner,
        route: HttpRouteFragment,
        log_tag: &str,
    ) -> Result<Self::Connection, Self::Error> {
        let HttpRouteFragment {
            host_header,
            path_prefix,
            http_version,
            front_name: _,
        } = route;

        if http_version != Some(HttpVersion::Http2) {
            return Err(HttpConnectError::InvalidConfig("wrong HTTP version"));
        }

        let info = over.transport_info();
        let io = TokioIo::new(over);
        let (sender, connection) = http2::Builder::new(TokioExecutor::new())
            .handshake::<_, B>(io)
            .await
            .map_err(|_: hyper::Error| HttpConnectError::HttpHandshake)?;

        // Starting a thread to drive client connection events.
        // The task will complete once the connection is closed due to an error
        // or if all clients are dropped.
        let log_tag = log_tag.to_owned();
        let ip_version = info.ip_version();
        tokio::spawn(async move {
            match connection.await {
                Ok(_) => log::info!("[{log_tag}] HTTP2 connection [{ip_version}] closed"),
                Err(err) => {
                    log::warn!("[{log_tag}] HTTP2 connection [{ip_version}] failed: {err}",)
                }
            }
        });

        let authority = http::uri::Authority::from_str(&host_header)
            .map_err(|_| HttpConnectError::InvalidConfig("invalid host"))?;
        let path_prefix = if path_prefix.is_empty() {
            None
        } else {
            Some(
                http::uri::PathAndQuery::from_str(&path_prefix)
                    .map_err(|_| HttpConnectError::InvalidConfig("invalid path prefix"))?,
            )
        };

        Ok(Http2Client {
            service: sender,
            authority,
            path_prefix,
        })
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::future::Future;
    use std::net::{IpAddr, Ipv6Addr, SocketAddr};
    use std::num::NonZeroU16;
    use std::ops::ControlFlow;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use assert_matches::assert_matches;
    use http::{HeaderName, HeaderValue, Method, StatusCode};
    use test_case::test_matrix;
    use warp::Filter as _;

    use super::*;
    use crate::OverrideNagleAlgorithm;
    use crate::host::Host;
    use crate::route::{
        ComposedConnector, ConnectError, ConnectionOutcomeParams, ConnectionOutcomes,
        HttpsTlsRoute, TcpRoute, ThrottlingConnector, TlsRoute, TlsRouteFragment,
    };
    use crate::tcp_ssl::testutil::{SERVER_CERTIFICATE, SERVER_HOSTNAME, localhost_https_server};

    const FAKE_RESPONSE: &str = "RESPONSE";
    const FAKE_RESPONSE_HEADER: (HeaderName, HeaderValue) = (
        HeaderName::from_static("response-header"),
        HeaderValue::from_static("response-value"),
    );
    const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

    struct RequestInfo {
        headers: warp::http::HeaderMap,
        method: warp::http::Method,
        version: warp::http::Version,
        path: String,
    }

    fn localhost_https_server_with_fake_response(
        write_request_to: std::sync::mpsc::Sender<RequestInfo>,
    ) -> (SocketAddr, impl Future<Output = ()>) {
        localhost_https_server(
            warp::any()
                .map(|| {
                    warp::reply::with_header(
                        FAKE_RESPONSE,
                        FAKE_RESPONSE_HEADER.0.as_str(),
                        FAKE_RESPONSE_HEADER.1.as_bytes(),
                    )
                })
                .with(warp::log::custom(move |info| {
                    let _ignore_error = write_request_to.send(RequestInfo {
                        headers: info.request_headers().clone(),
                        method: info.method().clone(),
                        path: info.path().to_string(),
                        version: info.version(),
                    });
                })),
        )
    }

    fn outcome_record_for_testing()
    -> tokio::sync::RwLock<ConnectionOutcomes<HttpsTlsRoute<TlsRoute<TcpRoute<IpAddr>>>>> {
        const MAX_DELAY: Duration = Duration::from_secs(100);
        const AGE_CUTOFF: Duration = Duration::from_secs(1000);
        const MAX_COUNT: u8 = 5;

        ConnectionOutcomes::new(ConnectionOutcomeParams {
            short_term_age_cutoff: AGE_CUTOFF,
            long_term_age_cutoff: AGE_CUTOFF,
            cooldown_growth_factor: 2.0,
            count_growth_factor: 10.0,
            max_count: MAX_COUNT,
            max_delay: MAX_DELAY,
        })
        .into()
    }

    // This was originally exposed as API from this module, and may be again in the future.
    async fn http2_client(
        targets: impl IntoIterator<Item = HttpsTlsRoute<TlsRoute<TcpRoute<IpAddr>>>>,
        outcome_record: &tokio::sync::RwLock<
            ConnectionOutcomes<HttpsTlsRoute<TlsRoute<TcpRoute<IpAddr>>>>,
        >,
        max_response_size: usize,
        log_tag: &str,
    ) -> Result<AggregatingHttp2Client, HttpError> {
        let mut outcome_record_snapshot = outcome_record.read().await.clone();
        let tls_connector = ComposedConnector::new(
            ThrottlingConnector::new(crate::tcp_ssl::StatelessTls, 1),
            crate::tcp_ssl::StatelessTcp,
        );
        let connector = ComposedConnector::new(Http2Connector::new(), tls_connector);
        let (result, updates) = crate::route::connect_resolved(
            targets.into_iter().collect(),
            &mut outcome_record_snapshot,
            connector,
            (),
            log_tag,
            |e| match e {
                HttpConnectError::Transport(t) => {
                    log::info!(
                        "[{log_tag}] HTTP2 connection failed: {}",
                        (&t as &dyn LogSafeDisplay)
                    );
                    ControlFlow::Continue(())
                }
                HttpConnectError::HttpHandshake => {
                    ControlFlow::Break(HttpError::Http2HandshakeFailed)
                }
                HttpConnectError::InvalidConfig(_) => {
                    ControlFlow::Break(HttpError::FailedToCreateRequest)
                }
            },
        )
        .await;

        outcome_record.write().await.apply_outcome_updates(
            updates.outcomes,
            updates.finished_at,
            SystemTime::now(),
        );

        Ok(AggregatingHttp2Client::new(
            result.map_err(|e| match e {
                ConnectError::AllAttemptsFailed | ConnectError::NoResolvedRoutes => {
                    HttpError::SslHandshakeFailed
                }
                ConnectError::FatalConnect(e) => e,
            })?,
            max_response_size,
        ))
    }

    #[test_matrix(["", "/prefix"])]
    #[tokio::test]
    async fn http_client_e2e_test(prefix: &'static str) {
        let _ = env_logger::try_init();
        let (request_info_send, request_info_recv) = std::sync::mpsc::channel();

        let (server_addr, server) = localhost_https_server_with_fake_response(request_info_send);
        tokio::spawn(server);

        const FAKE_HOSTNAME: &str = "different-from-sni.test-hostname";

        let host = FAKE_HOSTNAME.into();
        let mut client = http2_client(
            [HttpsTlsRoute {
                fragment: HttpRouteFragment {
                    host_header: Arc::clone(&host),
                    path_prefix: prefix.into(),
                    http_version: Some(HttpVersion::Http2),
                    front_name: None,
                },
                inner: TlsRoute {
                    fragment: TlsRouteFragment {
                        sni: Host::Domain(SERVER_HOSTNAME.into()),
                        root_certs: crate::certs::RootCertificates::FromDer(Cow::Borrowed(
                            SERVER_CERTIFICATE.cert.der(),
                        )),
                        alpn: Some(crate::Alpn::Http2),
                        min_protocol_version: None,
                    },
                    inner: TcpRoute {
                        address: Ipv6Addr::LOCALHOST.into(),
                        port: NonZeroU16::new(server_addr.port()).unwrap(),
                        override_nagle_algorithm: OverrideNagleAlgorithm::UseSystemDefault,
                    },
                },
            }],
            &outcome_record_for_testing(),
            MAX_RESPONSE_SIZE,
            "test",
        )
        .await
        .expect("can connect");

        let (response_parts, response_body) = client
            .send_request_aggregate_response(
                "/request/path".parse().unwrap(),
                Method::POST,
                HeaderMap::from_iter([(
                    HeaderName::from_static("test-header"),
                    HeaderValue::from_static("test-value"),
                )]),
                Bytes::new(),
            )
            .await
            .expect("request should succeed");

        let last_request = request_info_recv.recv().unwrap();

        assert_eq!(last_request.version, warp::http::Version::HTTP_2);
        assert_eq!(last_request.method, warp::http::Method::POST);
        assert_eq!(
            last_request.headers,
            warp::http::HeaderMap::from_iter(
                [("test-header", "test-value",), ("content-length", "0")]
                    .map(|(n, v)| (n.parse().unwrap(), v.parse().unwrap()))
            )
        );
        assert_eq!(last_request.path.as_str(), format!("{prefix}/request/path"));

        assert_eq!(response_parts.status, StatusCode::OK);
        assert_eq!(
            response_parts.headers.get(FAKE_RESPONSE_HEADER.0),
            Some(&FAKE_RESPONSE_HEADER.1)
        );

        assert_eq!(response_body, FAKE_RESPONSE);
    }

    /// Make sure that the code doesn't crash if a client passes in an invalid
    /// hostname.
    #[tokio::test]
    async fn http_client_invalid_hostname() {
        let _ = env_logger::try_init();

        let (request_info_send, _) = std::sync::mpsc::channel();

        let (server_addr, server) = localhost_https_server_with_fake_response(request_info_send);
        tokio::spawn(server);

        const INVALID_HOSTNAME: &str = "invalid hostname &&?";
        let host_header = INVALID_HOSTNAME.into();
        let err = http2_client(
            [HttpsTlsRoute {
                fragment: HttpRouteFragment {
                    host_header,
                    path_prefix: "".into(),
                    http_version: Some(HttpVersion::Http2),
                    front_name: None,
                },
                inner: TlsRoute {
                    fragment: TlsRouteFragment {
                        sni: Host::Domain(SERVER_HOSTNAME.into()),
                        root_certs: crate::certs::RootCertificates::FromDer(Cow::Borrowed(
                            SERVER_CERTIFICATE.cert.der(),
                        )),
                        alpn: None,
                        min_protocol_version: None,
                    },
                    inner: TcpRoute {
                        address: Ipv6Addr::LOCALHOST.into(),
                        port: NonZeroU16::new(server_addr.port()).unwrap(),
                        override_nagle_algorithm: OverrideNagleAlgorithm::UseSystemDefault,
                    },
                },
            }],
            &outcome_record_for_testing(),
            MAX_RESPONSE_SIZE,
            "test",
        )
        .await
        .expect_err("hostname checked here");

        assert_matches!(err, HttpError::FailedToCreateRequest);
    }
}
