//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::{Debug, Display};
use std::marker::PhantomData;
use std::time::Duration;

use derive_where::derive_where;
use futures_util::future::Either;
use futures_util::{Sink, Stream, TryFutureExt};
use http::uri::PathAndQuery;
use http_body_util::BodyExt;
use tungstenite::protocol::CloseFrame;
use tungstenite::{Message, Utf8Bytes, http};

use crate::AsyncDuplexStream;
use crate::errors::LogSafeDisplay;
use crate::http_client::{H2Body, Http2Client, Http2Connector};
use crate::route::{Connector, HttpRouteFragment, HttpVersion, WebSocketRouteFragment};
use crate::stream::StreamWithFixedTransportInfo;
use crate::ws::error::{HttpFormatError, ProtocolError, SpaceError};

pub mod error;
pub use error::WebSocketConnectError;

pub mod connection;
pub use connection::Connection;

pub mod attested;

/// Configuration values for managing the connected websocket.
#[derive(Clone, Copy)]
pub struct Config {
    /// How long to wait after the last outgoing message before sending a
    /// [`Message::Ping`].
    ///
    /// This time is measured across calls to [`Connection::handle_next_event`]
    /// from the last time an outgoing frame was sent.
    pub local_idle_timeout: Duration,

    /// The amount of time to wait after the last message received from the
    /// server before sending a [`Message::Ping`].
    ///
    /// This time is measured across calls to [`Connection::handle_next_event`],
    /// from the most recent message received from the server.
    pub remote_idle_ping_timeout: Duration,

    /// The amount of time to wait after the last message received from the
    /// server before disconnecting.
    ///
    /// This time is measured across calls to [`Connection::handle_next_event`],
    /// from the most recent message received from the server.
    ///
    /// This should be longer than [`Self::remote_idle_ping_timeout`] to allow
    /// the server time to respond to a sent ping before determining that the
    /// connection is dead.
    pub remote_idle_disconnect_timeout: Duration,
}

const WEBSOCKET_VERSION_VALUE: http::HeaderValue = http::HeaderValue::from_static("13");

/// A type that can be used like a [`tokio_tungstenite::WebSocketStream`].
///
/// This trait is blanket-implemented for types that can send and receive
/// [`tungstenite::Message`]s and [`tungstenite::Error`]s.
pub trait WebSocketStreamLike:
    Stream<Item = Result<tungstenite::Message, tungstenite::Error>>
    + Sink<tungstenite::Message, Error = tungstenite::Error>
{
}

impl<S> WebSocketStreamLike for S where
    S: Stream<Item = Result<tungstenite::Message, tungstenite::Error>>
        + Sink<tungstenite::Message, Error = tungstenite::Error>
{
}

/// A simplified version of [`tungstenite::Error`] that supports [`LogSafeDisplay`].
#[derive(Debug, thiserror::Error)]
pub enum WebSocketError {
    ChannelClosed,
    ChannelIdleTooLong,
    Io(std::io::Error),
    Protocol(ProtocolError),
    Capacity(SpaceError),
    Http(Box<http::Response<Option<Vec<u8>>>>),
    HttpFormat(http::Error),
    Url(tungstenite::error::UrlError),
    Other(&'static str),
}

/// A manual trait alias collecting the requirements for a websocket's transport stream.
///
/// May some day be replaceable by a language-provided trait alias,
/// <https://github.com/rust-lang/rust/issues/41517>.
pub trait WebSocketTransportStream:
    AsyncDuplexStream + crate::Connection + std::fmt::Debug + 'static
{
}
impl<T> WebSocketTransportStream for T where
    T: AsyncDuplexStream + crate::Connection + std::fmt::Debug + 'static
{
}

impl crate::Connection for Box<dyn WebSocketTransportStream> {
    fn transport_info(&self) -> crate::TransportInfo {
        (**self).transport_info()
    }
}

/// Stateless [`Connector`] implementation for websocket-over-HTTPS routes.
///
/// The `B` parameter controls what body type to use to allow sharing an underlying H2 connection
/// (it will be ignored for an H1 connection). If you don't care, use the default, which you can get
/// in expression contexts by using angle brackets: `<ws::Stateless>`.
#[derive_where(Default)]
pub struct Stateless<B = http_body_util::Empty<bytes::Bytes>> {
    // The connector does not itself carry a 'B', but it produces something that itself consumes
    // 'B's, which as far as variance goes is the same as consuming 'B's now. (This is probably
    // overthinking; the important part is that it's not just a plain B.)
    body: PhantomData<fn(B)>,
}

/// [`Connector`] for websocket-over-HTTPS routes that discards the response headers.
#[derive(Default)]
pub struct WithoutResponseHeaders<T = Stateless>(pub T);

impl WithoutResponseHeaders {
    /// Creates a [`Stateless`]-based `WithoutResponseHeaders`.
    ///
    /// Technically redundant with `default`, but doesn't leave any parameters up to inference.
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug)]
pub struct StreamWithResponseHeaders<Inner, B> {
    pub stream: Inner,
    pub response_headers: http::HeaderMap,
    pub connection: Option<Http2Client<B>>,
}

/// Connects a websocket on top of an existing connection.
///
/// This can't just take as the route type a [`WebSocketRouteFragment`] because
/// there are HTTP-level fields that also affect connection establishment.
impl<Inner, B> Connector<(WebSocketRouteFragment, HttpRouteFragment), Inner> for Stateless<B>
where
    Inner: WebSocketTransportStream,
    B: H2Body + Default,
{
    type Connection = StreamWithResponseHeaders<
        tokio_tungstenite::WebSocketStream<Box<dyn WebSocketTransportStream>>,
        B,
    >;

    type Error = WebSocketConnectError;

    fn connect_over(
        &self,
        inner: Inner,
        route: (WebSocketRouteFragment, HttpRouteFragment),
        log_tag: &str,
    ) -> impl std::future::Future<Output = Result<Self::Connection, Self::Error>> + Send {
        match route.1.http_version.unwrap_or(HttpVersion::Http1_1) {
            HttpVersion::Http1_1 => Either::Left(connect_http1(inner, route.0, route.1, log_tag)),
            HttpVersion::Http2 => Either::Right(connect_http2(inner, route.0, route.1, log_tag)),
        }
    }
}

async fn connect_http1<Inner: WebSocketTransportStream, B>(
    inner: Inner,
    ws: WebSocketRouteFragment,
    http: HttpRouteFragment,
    _log_tag: &str,
) -> Result<
    StreamWithResponseHeaders<
        tokio_tungstenite::WebSocketStream<Box<dyn WebSocketTransportStream>>,
        B,
    >,
    WebSocketConnectError,
> {
    let WebSocketRouteFragment {
        ws_config,
        endpoint,
        headers,
    } = ws;
    let HttpRouteFragment {
        host_header,
        path_prefix,
        http_version,
        front_name: _,
    } = http;

    if let Some(http_version) = http_version {
        debug_assert_eq!(
            http_version,
            HttpVersion::Http1_1,
            "can't connect over {http_version:?}",
        );
    }

    let uri_path = if path_prefix.is_empty() {
        endpoint
    } else {
        PathAndQuery::from_maybe_shared(format!("{path_prefix}{endpoint}"))
            .map_err(tungstenite::Error::from)?
    };

    let uri = http::uri::Builder::new()
        .path_and_query(uri_path)
        .authority(&*host_header)
        .scheme("wss")
        .build()
        .map_err(tungstenite::Error::from)?;

    let mut builder = http::Request::builder();
    *builder.headers_mut().expect("no headers, so not invalid") = headers;

    let request = builder
        .method(http::Method::GET)
        .uri(uri)
        .header(http::header::HOST, &*host_header)
        .header(http::header::CONNECTION, "Upgrade")
        .header(http::header::UPGRADE, "websocket")
        .header(http::header::SEC_WEBSOCKET_VERSION, WEBSOCKET_VERSION_VALUE)
        .header(
            http::header::SEC_WEBSOCKET_KEY,
            tungstenite::handshake::client::generate_key(),
        )
        .body(())
        .map_err(tungstenite::Error::from)?;

    let (stream, response) = tokio_tungstenite::client_async_with_config(
        request,
        Box::new(inner) as Box<dyn WebSocketTransportStream>,
        Some(ws_config),
    )
    .await?;

    Ok(StreamWithResponseHeaders {
        stream,
        response_headers: response.into_parts().0.headers,
        connection: None,
    })
}

async fn connect_http2<Inner: WebSocketTransportStream, B: H2Body + Default>(
    inner: Inner,
    ws: WebSocketRouteFragment,
    http: HttpRouteFragment,
    log_tag: &str,
) -> Result<
    StreamWithResponseHeaders<
        tokio_tungstenite::WebSocketStream<Box<dyn WebSocketTransportStream>>,
        B,
    >,
    WebSocketConnectError,
> {
    let WebSocketRouteFragment {
        ws_config,
        endpoint,
        headers,
    } = ws;
    let HttpRouteFragment {
        host_header: _,
        path_prefix: _,
        http_version,
        front_name: _,
    } = &http;

    debug_assert_eq!(
        *http_version,
        Some(HttpVersion::Http2),
        "can't connect over {http_version:?}",
    );

    if headers.contains_key(http::header::SEC_WEBSOCKET_EXTENSIONS) {
        log::error!(
            "cannot manually configure {}",
            http::header::SEC_WEBSOCKET_EXTENSIONS
        );
        return Err(WebSocketConnectError::Transport(
            crate::errors::TransportConnectError::InvalidConfiguration,
        ));
    }

    let h2_connector = Http2Connector::<B>::new();
    let transport_info = inner.transport_info();

    let mut client = h2_connector
        .connect_over(inner, http, log_tag)
        .await
        .map_err(|e| match e {
            crate::http_client::HttpConnectError::Transport(e) => {
                WebSocketConnectError::Transport(e)
            }
            crate::http_client::HttpConnectError::HttpHandshake => {
                WebSocketConnectError::WebSocketError(WebSocketError::Other("H2 handshake failed"))
            }
            crate::http_client::HttpConnectError::InvalidConfig(_msg) => {
                WebSocketConnectError::Transport(
                    crate::errors::TransportConnectError::InvalidConfiguration,
                )
            }
        })?;

    let mut builder = http::Request::builder();
    *builder.headers_mut().expect("no headers, so not invalid") = headers;

    let request = builder
        .method(http::Method::CONNECT)
        // Http2Client will rewrite this into an absolute URI for us.
        .uri(endpoint)
        .version(http::Version::HTTP_2)
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .header(http::header::SEC_WEBSOCKET_VERSION, WEBSOCKET_VERSION_VALUE)
        .body(Default::default())
        .map_err(tungstenite::Error::from)?;

    let response = async {
        client.ready().await?;
        client.send_request(request).await
    }
    .await
    .map_err(|e: hyper::Error| {
        log::debug!("[{log_tag}] websocket upgrade failed: {e}");
        // hyper::Error isn't an enum; we have to infer what to report this as.
        if e.is_timeout() {
            WebSocketError::Io(std::io::ErrorKind::TimedOut.into())
        } else if e.is_canceled() || e.is_closed() || e.is_incomplete_message() {
            WebSocketError::ChannelClosed
        } else if e.is_parse() {
            WebSocketError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP parse error",
            ))
        } else {
            WebSocketError::Io(std::io::Error::other(
                "failed to complete H2 websocket upgrade request",
            ))
        }
    })?;

    // We mostly skip validating the response; doing so properly belongs in tungstenite itself[1],
    // and we assume that any issues will get caught when using the channel anyway. The only thing
    // we do is check the return status, which is different for H2 (RFC 8441): following the
    // requirements for the CONNECT method, any 2xx status is fine.
    //
    // [1]: https://github.com/snapview/tungstenite-rs/blob/v0.28.0/src/handshake/client.rs#L223
    if !response.status().is_success() {
        // Collect the body to produce an all-in-one http::Request. But we'll ignore errors
        // collecting the body; if it fails, we'd rather return an HTTP error with the correct
        // status and no body than an IO error of some kind.
        let (head, body) = response.into_parts();
        let body = body
            .collect()
            .await
            .ok()
            .map(|collected| collected.to_bytes().into());
        let response = http::Response::from_parts(head, body);
        return Err(WebSocketConnectError::WebSocketError(WebSocketError::Http(
            Box::new(response),
        )));
    }

    if let Some(extensions) = response
        .headers()
        .get(http::header::SEC_WEBSOCKET_EXTENSIONS)
    {
        log::error!(
            "server provided {} even though we didn't send any",
            http::header::SEC_WEBSOCKET_EXTENSIONS
        );
        log::debug!(
            "{}: {}",
            http::header::SEC_WEBSOCKET_EXTENSIONS,
            extensions.as_bytes().escape_ascii()
        );
        return Err(tungstenite::Error::Protocol(
            tungstenite::error::ProtocolError::InvalidHeader(
                http::header::SEC_WEBSOCKET_EXTENSIONS,
            ),
        )
        .into());
    }

    // We can't just take() the response headers because hyper::upgrade might need them.
    let response_headers = response.headers().clone();

    let stream = hyper::upgrade::on(response)
        .await
        .map_err(|e: hyper::Error| {
            log::debug!("[{log_tag}] websocket upgrade failed: {e}");
            WebSocketConnectError::WebSocketError(WebSocketError::Other(
                "failed to complete H2 websocket upgrade",
            ))
        })?;

    let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        Box::new(StreamWithFixedTransportInfo::new(
            hyper_util::rt::TokioIo::new(stream),
            transport_info,
        )) as Box<dyn WebSocketTransportStream>,
        tungstenite::protocol::Role::Client,
        Some(ws_config),
    )
    .await;

    Ok(StreamWithResponseHeaders {
        stream: ws,
        response_headers,
        connection: Some(client),
    })
}

impl<T, Inner, C, B> Connector<(WebSocketRouteFragment, HttpRouteFragment), Inner>
    for WithoutResponseHeaders<T>
where
    T: Connector<
            (WebSocketRouteFragment, HttpRouteFragment),
            Inner,
            Connection = StreamWithResponseHeaders<C, B>,
        >,
{
    type Connection = C;
    type Error = T::Error;

    fn connect_over(
        &self,
        inner: Inner,
        route: (WebSocketRouteFragment, HttpRouteFragment),
        log_tag: &str,
    ) -> impl std::future::Future<Output = Result<Self::Connection, Self::Error>> + Send {
        self.0.connect_over(inner, route, log_tag).map_ok(
            |StreamWithResponseHeaders {
                 stream,
                 response_headers: _,
                 connection: _,
             }| stream,
        )
    }
}

impl LogSafeDisplay for WebSocketError {}
impl Display for WebSocketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebSocketError::ChannelClosed => write!(f, "channel already closed"),
            WebSocketError::ChannelIdleTooLong => write!(f, "channel was idle for too long"),
            WebSocketError::Io(e) => write!(f, "IO error: {}", e.kind()),
            WebSocketError::Protocol(p) => {
                write!(f, "websocket protocol: {}", p.clone())
            }
            WebSocketError::Capacity(e) => write!(f, "capacity error: {e}"),
            WebSocketError::Http(response) => write!(f, "HTTP error: {}", response.status()),
            WebSocketError::HttpFormat(e) => {
                write!(f, "HTTP format error: {}", HttpFormatError::from(e))
            }
            WebSocketError::Url(_) => write!(f, "URL error"),
            WebSocketError::Other(message) => write!(f, "other web socket error: {message}"),
        }
    }
}

impl From<tungstenite::Error> for WebSocketError {
    fn from(value: tungstenite::Error) -> Self {
        match value {
            tungstenite::Error::ConnectionClosed => Self::ChannelClosed,
            tungstenite::Error::AlreadyClosed => Self::ChannelClosed,
            tungstenite::Error::Io(e) => Self::Io(e),
            tungstenite::Error::Protocol(e) => Self::Protocol(e.into()),
            tungstenite::Error::Capacity(e) => Self::Capacity(e.into()),
            tungstenite::Error::WriteBufferFull(_) => Self::Capacity(SpaceError::SendQueueFull),
            tungstenite::Error::Url(e) => Self::Url(e),
            tungstenite::Error::Http(response) => Self::Http(Box::new(response)),
            tungstenite::Error::HttpFormat(e) => Self::HttpFormat(e),
            tungstenite::Error::Utf8(_) => Self::Other("UTF-8 error"),
            tungstenite::Error::AttackAttempt => Self::Other("attack attempt"),
            tungstenite::Error::Tls(_) => unreachable!("all TLS is handled below tungstenite"),
        }
    }
}

#[derive(Debug, derive_more::From)]
#[cfg_attr(any(test, feature = "test-util"), derive(Clone, Eq, PartialEq))]
pub enum TextOrBinary {
    #[from(Utf8Bytes, String, &str)]
    Text(Utf8Bytes),
    #[from(bytes::Bytes, Vec<u8>)]
    Binary(bytes::Bytes),
}

impl From<TextOrBinary> for Message {
    fn from(value: TextOrBinary) -> Self {
        match value {
            TextOrBinary::Binary(b) => Self::Binary(b),
            TextOrBinary::Text(t) => Self::Text(t),
        }
    }
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(any(test, feature = "test-util"), derive(Debug))]
pub enum NextOrClose<T> {
    Next(T),
    Close(Option<CloseFrame>),
}

impl<T> NextOrClose<T> {
    pub fn next_or<E>(self, failure: E) -> Result<T, E> {
        match self {
            Self::Close(_) => Err(failure),
            Self::Next(t) => Ok(t),
        }
    }

    pub fn next_or_else<E>(self, on_close: impl FnOnce(Option<CloseFrame>) -> E) -> Result<T, E> {
        match self {
            Self::Next(t) => Ok(t),
            Self::Close(close) => Err(on_close(close)),
        }
    }
}

impl<S: crate::Connection + tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> crate::Connection
    for tokio_tungstenite::WebSocketStream<S>
{
    fn transport_info(&self) -> crate::TransportInfo {
        self.get_ref().transport_info()
    }
}

/// Test utilities related to websockets.
#[cfg(any(test, feature = "test-util"))]
#[allow(clippy::unwrap_used)]
pub mod testutil {
    use std::net::{Ipv4Addr, SocketAddr};

    use tokio::io::DuplexStream;
    use tokio_tungstenite::WebSocketStream;
    use tungstenite::protocol::WebSocketConfig;

    use super::*;
    use crate::TransportInfo;

    pub async fn fake_websocket() -> (
        WebSocketStream<DuplexStream>,
        WebSocketStream<Box<dyn WebSocketTransportStream>>,
    ) {
        let (client, server) = tokio::io::duplex(1024);
        let connector = WithoutResponseHeaders::new();
        let client_future = connector.connect_over(
            client,
            (
                WebSocketRouteFragment {
                    ws_config: WebSocketConfig::default(),
                    endpoint: PathAndQuery::from_static("/"),
                    headers: Default::default(),
                },
                HttpRouteFragment {
                    host_header: "localhost".into(),
                    path_prefix: "".into(),
                    http_version: Some(HttpVersion::Http1_1),
                    front_name: None,
                },
            ),
            "test",
        );
        let server_future = tokio_tungstenite::accept_async(server);
        let (client_res, server_res) = tokio::join!(client_future, server_future);
        let client_stream = client_res.unwrap();
        let server_stream = server_res.unwrap();
        (server_stream, client_stream)
    }

    impl crate::Connection for DuplexStream {
        fn transport_info(&self) -> TransportInfo {
            TransportInfo {
                local_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
                remote_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::borrow::Cow;
    use std::num::NonZero;
    use std::pin::pin;
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use futures_util::future::BoxFuture;
    use futures_util::{SinkExt as _, StreamExt as _};
    use http::uri::PathAndQuery;
    use tokio::sync::mpsc;
    use tokio_boring_signal::SslStream;

    use super::testutil::*;
    use super::*;
    use crate::certs::RootCertificates;
    use crate::host::Host;
    use crate::route::{
        ComposedConnector, ConnectorExt as _, TcpRoute, TlsRoute, TlsRouteFragment,
    };
    use crate::tcp_ssl::testutil::{
        SERVER_CERTIFICATE, SERVER_HOSTNAME, localhost_https_server_with_custom_service,
    };
    use crate::tcp_ssl::{StatelessTcp, StatelessTls};
    use crate::{Alpn, Connection, OverrideNagleAlgorithm};

    #[tokio::test]
    async fn websocket_client_sends_pong_on_server_ping() {
        let (mut server, mut client) = fake_websocket().await;
        // starting a client that only listens to the incoming messages,
        // but not sending any responses on its own
        let _client = tokio::spawn(async move { while let Some(Ok(_)) = client.next().await {} });
        server.send(Message::Ping(vec![].into())).await.unwrap();
        let response = server
            .next()
            .await
            .expect("some result")
            .expect("ok result");
        assert_eq!(response, Message::Pong(vec![].into()));
    }

    struct LocalH2WebSocketOptions {
        extra_expected_headers: http::HeaderMap,
        extra_response_headers: http::HeaderMap,
        expected_path_and_query: PathAndQuery,
    }

    impl Default for LocalH2WebSocketOptions {
        fn default() -> Self {
            Self {
                extra_expected_headers: Default::default(),
                extra_response_headers: Default::default(),
                expected_path_and_query: PathAndQuery::from_static("/"),
            }
        }
    }

    /// Runs an H2 server on `::1`, and connects a transport stream to it.
    ///
    /// Returns the connected transport stream as well as the server Future; the server must be
    /// polled (or spawned onto its own tokio task) for the connection to do anything.
    async fn localhost_h2_ws(
        upgrade_failure_tx: mpsc::Sender<hyper::Error>,
        options: LocalH2WebSocketOptions,
    ) -> (
        SslStream<impl AsyncDuplexStream + Connection + Debug>,
        BoxFuture<'static, ()>,
    ) {
        let LocalH2WebSocketOptions {
            extra_expected_headers: mut expected_headers,
            extra_response_headers,
            expected_path_and_query,
        } = options;

        expected_headers.append(http::header::SEC_WEBSOCKET_VERSION, WEBSOCKET_VERSION_VALUE);
        let expected_headers = Arc::new(expected_headers);

        let (addr, server) = localhost_https_server_with_custom_service(
            Alpn::Http2.length_prefixed(),
            hyper::service::service_fn(move |mut req| {
                let upgrade_failure_tx = upgrade_failure_tx.clone();
                let expected_headers = expected_headers.clone();
                let extra_response_headers = extra_response_headers.clone();
                let expected_path_and_query = expected_path_and_query.clone();
                async move {
                    if req.method() != http::Method::CONNECT {
                        return Ok(http::Response::builder()
                            .status(http::StatusCode::METHOD_NOT_ALLOWED)
                            .body(format!("wrong method '{}'", req.method()))
                            .expect("valid"));
                    }

                    match req.extensions().get::<hyper::ext::Protocol>() {
                        Some(protocol) if protocol.as_str() == "websocket" => {}
                        Some(protocol) => {
                            return Ok(http::Response::builder()
                                .status(http::StatusCode::BAD_REQUEST)
                                .body(format!("wrong protocol '{}'", protocol.as_str()))
                                .expect("valid"));
                        }
                        None => {
                            return Ok(http::Response::builder()
                                .status(http::StatusCode::BAD_REQUEST)
                                .body("missing protocol".to_owned())
                                .expect("valid"));
                        }
                    }

                    if req.uri().path_and_query() != Some(&expected_path_and_query) {
                        return Ok(http::Response::builder()
                            .status(http::StatusCode::BAD_REQUEST)
                            .body(format!(
                                "incorrect path\nexpected: {}\nactual: {:?}",
                                expected_path_and_query,
                                req.uri()
                                    .path_and_query()
                                    .map(|p| p.as_str())
                                    .unwrap_or_default()
                            ))
                            .expect("valid"));
                    }

                    if *expected_headers != *req.headers() {
                        return Ok(http::Response::builder()
                            .status(400)
                            .body(format!(
                                "incorrect headers\nexpected: {:#?}\nactual: {:#?}",
                                expected_headers,
                                req.headers()
                            ))
                            .expect("valid"));
                    }

                    tokio::spawn(async move {
                        match hyper::upgrade::on(&mut req).await {
                            Ok(upgraded) => {
                                // Immediately close the connection, we're only testing establishment.
                                let mut ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
                                    hyper_util::rt::TokioIo::new(upgraded),
                                    tungstenite::protocol::Role::Server,
                                    None,
                                )
                                .await;
                                ws.close(None).await.expect("can close");
                                // Let the client ack the close, so they can exit cleanly.
                                while ws.next().await.is_some() {}
                            }
                            Err(e) => {
                                _ = upgrade_failure_tx.send(e).await;
                            }
                        }
                    });

                    let mut response = http::Response::builder();
                    *response.headers_mut().expect("valid") = extra_response_headers;
                    Ok::<_, std::convert::Infallible>(response.body(String::new()).expect("valid"))
                }
            }),
        );
        let server = Box::pin(server);

        type StatelessTlsConnector = ComposedConnector<StatelessTls, StatelessTcp>;
        let connector = StatelessTlsConnector::default();
        let client = pin!(connector.connect(
            TlsRoute {
                fragment: TlsRouteFragment {
                    root_certs: RootCertificates::FromDer(Cow::Borrowed(
                        SERVER_CERTIFICATE.cert.der(),
                    )),
                    sni: Host::Domain(SERVER_HOSTNAME.into()),
                    alpn: Some(Alpn::Http2),
                    min_protocol_version: None,
                },
                inner: TcpRoute {
                    address: addr.ip(),
                    port: NonZero::new(addr.port()).expect("successful listener has a valid port"),
                    override_nagle_algorithm: OverrideNagleAlgorithm::UseSystemDefault,
                },
            },
            "transport",
        ));

        match futures_util::future::select(client, server).await {
            Either::Left((stream, server)) => {
                (stream.expect("client connects successfully"), server)
            }
            Either::Right(_) => panic!("server exited unexpectedly"),
        }
    }

    #[test_log::test(tokio::test)]
    async fn ws_over_h2() {
        let (upgrade_failure_tx, mut upgrade_failure_rx) = mpsc::channel(1);
        let testing_header_pair = (
            http::HeaderName::from_static("x-testing"),
            http::HeaderValue::from_static("test"),
        );
        let extra_expected_headers = http::HeaderMap::from_iter([testing_header_pair.clone()]);
        let (stream, server) = localhost_h2_ws(
            upgrade_failure_tx,
            LocalH2WebSocketOptions {
                extra_expected_headers,
                ..Default::default()
            },
        )
        .await;
        let server_task = tokio::spawn(server);

        let mut ws = <Stateless>::default()
            .connect_over(
                stream,
                (
                    WebSocketRouteFragment {
                        ws_config: Default::default(),
                        endpoint: PathAndQuery::from_static("/"),
                        headers: http::HeaderMap::from_iter([testing_header_pair]),
                    },
                    HttpRouteFragment {
                        host_header: "test.local".into(),
                        path_prefix: "".into(),
                        http_version: Some(HttpVersion::Http2),
                        front_name: None,
                    },
                ),
                "ws",
            )
            .await
            .expect("can connect");

        let frame = ws
            .stream
            .next()
            .await
            .expect("has close frame")
            .expect("no error");
        assert_matches!(frame, tungstenite::Message::Close(None));
        assert_matches!(ws.stream.next().await, None, "should be closed now");

        server_task.abort();
        assert_matches!(upgrade_failure_rx.recv().await, None);
    }

    #[test_log::test(tokio::test)]
    async fn ws_over_h2_handles_rejected_by_server() {
        let (upgrade_failure_tx, _upgrade_failure_rx) = mpsc::channel(1);
        let (stream, server) = localhost_h2_ws(upgrade_failure_tx, Default::default()).await;
        tokio::spawn(server);

        let err = <Stateless>::default()
            .connect_over(
                stream,
                (
                    WebSocketRouteFragment {
                        ws_config: Default::default(),
                        endpoint: PathAndQuery::from_static("/"),
                        // Induce a failure by passing unexpected headers.
                        headers: http::HeaderMap::from_iter([(
                            http::HeaderName::from_static("x-testing"),
                            http::HeaderValue::from_static("bad"),
                        )]),
                    },
                    HttpRouteFragment {
                        host_header: "test.local".into(),
                        path_prefix: "".into(),
                        http_version: Some(HttpVersion::Http2),
                        front_name: None,
                    },
                ),
                "ws",
            )
            .await
            .expect_err("should fail");

        let response = assert_matches!(
            err,
            WebSocketConnectError::WebSocketError(WebSocketError::Http(response)) =>
            response
        );
        assert_eq!(response.status(), http::StatusCode::BAD_REQUEST);
    }

    #[test_log::test(tokio::test)]
    async fn ws_over_h2_handles_io_error() {
        let (upgrade_failure_tx, _upgrade_failure_rx) = mpsc::channel(1);
        let (stream, server) = localhost_h2_ws(upgrade_failure_tx, Default::default()).await;
        // "Oops, the server dropped the connection."
        drop(server);

        let err = <Stateless>::default()
            .connect_over(
                stream,
                (
                    WebSocketRouteFragment {
                        ws_config: Default::default(),
                        endpoint: PathAndQuery::from_static("/"),
                        headers: http::HeaderMap::new(),
                    },
                    HttpRouteFragment {
                        host_header: "test.local".into(),
                        path_prefix: "".into(),
                        http_version: Some(HttpVersion::Http2),
                        front_name: None,
                    },
                ),
                "ws",
            )
            .await
            .expect_err("should fail");

        assert_matches!(
            err,
            WebSocketConnectError::WebSocketError(WebSocketError::ChannelClosed)
        );
    }

    #[test_log::test(tokio::test)]
    async fn ws_over_h2_handles_unexpected_ws_extensions() {
        let (upgrade_failure_tx, _upgrade_failure_rx) = mpsc::channel(1);
        let (stream, server) = localhost_h2_ws(
            upgrade_failure_tx,
            LocalH2WebSocketOptions {
                extra_response_headers: http::HeaderMap::from_iter([(
                    http::header::SEC_WEBSOCKET_EXTENSIONS,
                    http::HeaderValue::from_static("unexpected-extension"),
                )]),
                ..Default::default()
            },
        )
        .await;
        tokio::spawn(server);

        let err = <Stateless>::default()
            .connect_over(
                stream,
                (
                    WebSocketRouteFragment {
                        ws_config: Default::default(),
                        endpoint: PathAndQuery::from_static("/"),
                        headers: http::HeaderMap::new(),
                    },
                    HttpRouteFragment {
                        host_header: "test.local".into(),
                        path_prefix: "".into(),
                        http_version: Some(HttpVersion::Http2),
                        front_name: None,
                    },
                ),
                "ws",
            )
            .await
            .expect_err("should fail");

        assert_matches!(
            err,
            WebSocketConnectError::WebSocketError(WebSocketError::Protocol(
                ProtocolError(tungstenite::error::ProtocolError::InvalidHeader(h))
            )) if h == http::header::SEC_WEBSOCKET_EXTENSIONS
        );
    }

    #[test_log::test(tokio::test)]
    async fn ws_over_h2_applies_path_prefix_correctly() {
        let (upgrade_failure_tx, mut upgrade_failure_rx) = mpsc::channel(1);

        let path_prefix = "/service";
        let endpoint = PathAndQuery::from_static("/chat");
        let expected_path_and_query = PathAndQuery::from_static("/service/chat");

        let (stream, server) = localhost_h2_ws(
            upgrade_failure_tx,
            LocalH2WebSocketOptions {
                expected_path_and_query,
                ..Default::default()
            },
        )
        .await;
        let server_task = tokio::spawn(server);

        let mut ws = <Stateless>::default()
            .connect_over(
                stream,
                (
                    WebSocketRouteFragment {
                        ws_config: Default::default(),
                        endpoint,
                        headers: http::HeaderMap::new(),
                    },
                    HttpRouteFragment {
                        host_header: "test.local".into(),
                        path_prefix: path_prefix.into(),
                        http_version: Some(HttpVersion::Http2),
                        front_name: None,
                    },
                ),
                "ws",
            )
            .await
            .expect("can connect");

        // Server immediately closes after upgrade; ensure we see that frame.
        let frame = ws
            .stream
            .next()
            .await
            .expect("has close frame")
            .expect("no error");
        assert_matches!(frame, tungstenite::Message::Close(None));
        assert_matches!(ws.stream.next().await, None, "should be closed now");

        server_task.abort();
        assert_matches!(upgrade_failure_rx.recv().await, None);
    }
}
