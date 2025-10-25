//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::Arc;

use bytes::Bytes;
use http::HeaderMap;
use http::response::Parts;
use http::uri::PathAndQuery;
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use static_assertions::assert_impl_all;

use crate::errors::{LogSafeDisplay, TransportConnectError};
use crate::route::{Connector, HttpRouteFragment, HttpsTlsRoute};
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

#[derive(Debug, Clone)]
pub struct AggregatingHttp2Client {
    service: http2::SendRequest<Full<Bytes>>,
    http_host: Arc<str>,
    max_response_size: usize,
    path_prefix: Arc<str>,
}

impl AggregatingHttp2Client {
    pub async fn send_request_aggregate_response(
        &self,
        path_and_query: PathAndQuery,
        method: http::Method,
        headers: HeaderMap,
        body: Bytes,
    ) -> Result<(Parts, Bytes), HttpError> {
        let uri = format!(
            "https://{}{}{}",
            self.http_host, self.path_prefix, path_and_query
        );
        let mut request_builder = http::Request::builder()
            .method(method)
            .uri(uri)
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

        let res = self
            .service
            .clone()
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
pub(crate) struct Http2Connector<C> {
    pub inner: C,
    pub max_response_size: usize,
}

#[derive(derive_more::From, displaydoc::Display)]
pub(crate) enum HttpConnectError {
    /// {0}
    Transport(#[from] TransportConnectError),
    /// HTTP handshake failed
    HttpHandshake,
}

assert_impl_all!(TransportConnectError: LogSafeDisplay);
impl LogSafeDisplay for HttpConnectError {}

impl<T, C, Inner> Connector<HttpsTlsRoute<T>, Inner> for Http2Connector<C>
where
    C: Connector<
            T,
            Inner,
            Connection: Connection + Send + AsyncDuplexStream + 'static,
            Error = TransportConnectError,
        > + Sync,
    Inner: Send,
    T: Send,
{
    type Connection = AggregatingHttp2Client;

    type Error = HttpConnectError;

    async fn connect_over(
        &self,
        over: Inner,
        route: HttpsTlsRoute<T>,
        log_tag: &str,
    ) -> Result<Self::Connection, Self::Error> {
        let HttpsTlsRoute {
            fragment:
                HttpRouteFragment {
                    host_header,
                    path_prefix,
                    front_name: _,
                },
            inner: tls_target,
        } = route;

        let ssl_stream = self.inner.connect_over(over, tls_target, log_tag).await?;
        let info = ssl_stream.transport_info();
        let io = TokioIo::new(ssl_stream);
        let (sender, connection) = http2::handshake::<_, _, Full<Bytes>>(TokioExecutor::new(), io)
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

        Ok(AggregatingHttp2Client {
            service: sender,
            http_host: host_header,
            path_prefix,
            max_response_size: self.max_response_size,
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
    use std::time::{Duration, SystemTime};

    use assert_matches::assert_matches;
    use http::{HeaderName, HeaderValue, Method, StatusCode};
    use warp::Filter as _;

    use super::*;
    use crate::host::Host;
    use crate::route::{
        ConnectError, ConnectionOutcomeParams, ConnectionOutcomes, TcpRoute, ThrottlingConnector,
        TlsRoute, TlsRouteFragment,
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
        let tls_connector = crate::route::ComposedConnector::new(
            ThrottlingConnector::new(crate::tcp_ssl::StatelessTls, 1),
            crate::tcp_ssl::StatelessTcp,
        );
        let connector = Http2Connector {
            inner: tls_connector,
            max_response_size,
        };
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
            },
        )
        .await;

        outcome_record.write().await.apply_outcome_updates(
            updates.outcomes,
            updates.finished_at,
            SystemTime::now(),
        );

        result.map_err(|e| match e {
            ConnectError::AllAttemptsFailed | ConnectError::NoResolvedRoutes => {
                HttpError::SslHandshakeFailed
            }
            ConnectError::FatalConnect(e) => e,
        })
    }

    #[tokio::test]
    async fn http_client_e2e_test() {
        let _ = env_logger::try_init();
        let (request_info_send, request_info_recv) = std::sync::mpsc::channel();

        let (server_addr, server) = localhost_https_server_with_fake_response(request_info_send);
        tokio::spawn(server);

        const FAKE_HOSTNAME: &str = "different-from-sni.test-hostname";

        let host = FAKE_HOSTNAME.into();
        let client = http2_client(
            [HttpsTlsRoute {
                fragment: HttpRouteFragment {
                    host_header: Arc::clone(&host),
                    path_prefix: "".into(),
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
        assert_eq!(last_request.path.as_str(), "/request/path");

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
        let client = http2_client(
            [HttpsTlsRoute {
                fragment: HttpRouteFragment {
                    host_header,
                    path_prefix: "".into(),
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
                    },
                },
            }],
            &outcome_record_for_testing(),
            MAX_RESPONSE_SIZE,
            "test",
        )
        .await
        .expect("can connect");

        let result = client
            .send_request_aggregate_response(
                "/request/path".parse().unwrap(),
                Method::POST,
                HeaderMap::from_iter([(
                    HeaderName::from_static("test-header"),
                    HeaderValue::from_static("test-value"),
                )]),
                Bytes::new(),
            )
            .await;

        assert_matches!(result, Err(HttpError::FailedToCreateRequest));
    }
}
