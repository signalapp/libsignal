//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::{Debug, Display};
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use derive_where::derive_where;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{Sink, SinkExt as _, Stream, StreamExt, TryFutureExt};
use http::uri::PathAndQuery;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tokio_tungstenite::WebSocketStream;
use tungstenite::protocol::CloseFrame;
use tungstenite::{http, Message};

use crate::errors::LogSafeDisplay;
use crate::route::{Connector, HttpRouteFragment, WebSocketRouteFragment};
use crate::service::{CancellationReason, CancellationToken};
use crate::ws::error::{HttpFormatError, ProtocolError, SpaceError};
use crate::{AsyncDuplexStream, Connection};

pub mod error;
pub use error::{LogSafeTungsteniteError, WebSocketConnectError};

mod noise;
pub use noise::WebSocketTransport;

/// Configuration for a websocket connection.
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// Protocol-level configuration.
    pub ws_config: tungstenite::protocol::WebSocketConfig,
    /// The HTTP path to use when establishing the websocket connection.
    pub endpoint: PathAndQuery,
    /// How long to wait after the request before timing out the connection.
    ///
    /// The amount of time after sending the request with the [`Upgrade`]
    /// header on HTTP/1.1, or [`CONNECT`] method on HTTP/2, before which the
    /// server should be assumed to be unavailable and the connection defunct.
    ///
    /// [`Upgrade`]: http::header::UPGRADE
    /// [`CONNECT`]: http::method::Method::CONNECT
    pub max_connection_time: Duration,
    /// How often to send [`Ping`] frames on the connection.
    ///
    /// [`Ping`]: tungstenite::Message::Ping
    pub keep_alive_interval: Duration,
    /// How long to allow the connection to be idle before the server is assumed
    /// to have become unavailable.
    pub max_idle_time: Duration,
}

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

impl WebSocketConfig {
    pub fn ws2_config(&self) -> crate::ws2::Config {
        crate::ws2::Config {
            local_idle_timeout: self.keep_alive_interval,
            remote_idle_ping_timeout: self.keep_alive_interval,
            remote_idle_disconnect_timeout: self.max_idle_time,
        }
    }
}

/// A simplified version of [`tungstenite::Error`] that supports [`LogSafeDisplay`].
#[derive(Debug, thiserror::Error)]
pub enum WebSocketServiceError {
    ChannelClosed,
    ChannelIdleTooLong,
    Io(std::io::Error),
    Protocol(ProtocolError),
    Capacity(SpaceError),
    Http(http::Response<Option<Vec<u8>>>),
    HttpFormat(http::Error),
    Url(tungstenite::error::UrlError),
    Other(&'static str),
}

/// Stateless [`Connector`] implementation for websocket-over-HTTPS routes.
#[derive(Default)]
pub struct Stateless;

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
pub struct StreamWithResponseHeaders<Inner> {
    pub stream: Inner,
    pub response_headers: http::HeaderMap,
}

/// Connects a websocket on top of an existing connection.
///
/// This can't just take as the route type a [`WebSocketRouteFragment`] because
/// there are HTTP-level fields that also affect connection establishment.
/// Conversely, a [`Connector`] for just a [`HttpRouteFragment`] doesn't make
/// sense because there's no HTTP-level handshaking that establishes an HTTP
/// connection (before HTTP/2).
impl<Inner> Connector<(WebSocketRouteFragment, HttpRouteFragment), Inner> for Stateless
where
    Inner: AsyncDuplexStream,
{
    type Connection = StreamWithResponseHeaders<tokio_tungstenite::WebSocketStream<Inner>>;

    type Error = WebSocketConnectError;

    fn connect_over(
        &self,
        inner: Inner,
        route: (WebSocketRouteFragment, HttpRouteFragment),
        _log_tag: Arc<str>,
    ) -> impl std::future::Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let (
            WebSocketRouteFragment {
                ws_config,
                endpoint,
                headers,
            },
            HttpRouteFragment {
                host_header,
                path_prefix,
                front_name: _,
            },
        ) = route;

        let uri_path = if path_prefix.is_empty() {
            Ok(endpoint)
        } else {
            PathAndQuery::from_maybe_shared(format!("{path_prefix}{endpoint}"))
                .map_err(tungstenite::Error::from)
        };

        async move {
            let uri = http::uri::Builder::new()
                .path_and_query(uri_path?)
                .authority(&*host_header)
                .scheme("wss")
                .build()
                .map_err(tungstenite::Error::from)?;

            let mut builder = http::Request::builder();
            *builder.headers_mut().expect("no headers, so not invalid") = headers;

            let request = builder
                .header(http::header::HOST, &*host_header)
                .uri(uri)
                .method(http::Method::GET)
                .header(http::header::CONNECTION, "Upgrade")
                .header(http::header::UPGRADE, "websocket")
                .header(http::header::SEC_WEBSOCKET_VERSION, "13")
                .header(
                    http::header::SEC_WEBSOCKET_KEY,
                    tungstenite::handshake::client::generate_key(),
                )
                .body(())
                .map_err(tungstenite::Error::from)?;

            let (stream, response) =
                tokio_tungstenite::client_async_with_config(request, inner, Some(ws_config))
                    .await?;

            Ok(StreamWithResponseHeaders {
                stream,
                response_headers: response.into_parts().0.headers,
            })
        }
    }
}

impl<T, Inner> Connector<(WebSocketRouteFragment, HttpRouteFragment), Inner>
    for WithoutResponseHeaders<T>
where
    T: Connector<
        (WebSocketRouteFragment, HttpRouteFragment),
        Inner,
        Connection = StreamWithResponseHeaders<tokio_tungstenite::WebSocketStream<Inner>>,
    >,
{
    type Connection = tokio_tungstenite::WebSocketStream<Inner>;
    type Error = T::Error;

    fn connect_over(
        &self,
        inner: Inner,
        route: (WebSocketRouteFragment, HttpRouteFragment),
        log_tag: Arc<str>,
    ) -> impl std::future::Future<Output = Result<Self::Connection, Self::Error>> + Send {
        self.0.connect_over(inner, route, log_tag).map_ok(
            |StreamWithResponseHeaders {
                 stream,
                 response_headers: _,
             }| stream,
        )
    }
}

impl LogSafeDisplay for WebSocketServiceError {}
impl Display for WebSocketServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebSocketServiceError::ChannelClosed => write!(f, "channel already closed"),
            WebSocketServiceError::ChannelIdleTooLong => write!(f, "channel was idle for too long"),
            WebSocketServiceError::Io(e) => write!(f, "IO error: {}", e.kind()),
            WebSocketServiceError::Protocol(p) => {
                write!(f, "websocket protocol: {}", p.clone())
            }
            WebSocketServiceError::Capacity(e) => write!(f, "capacity error: {e}"),
            WebSocketServiceError::Http(response) => write!(f, "HTTP error: {}", response.status()),
            WebSocketServiceError::HttpFormat(e) => {
                write!(f, "HTTP format error: {}", HttpFormatError::from(e))
            }
            WebSocketServiceError::Url(_) => write!(f, "URL error"),
            WebSocketServiceError::Other(message) => write!(f, "other web socket error: {message}"),
        }
    }
}

impl From<tungstenite::Error> for WebSocketServiceError {
    fn from(value: tungstenite::Error) -> Self {
        match value {
            tungstenite::Error::ConnectionClosed => Self::ChannelClosed,
            tungstenite::Error::AlreadyClosed => Self::ChannelClosed,
            tungstenite::Error::Io(e) => Self::Io(e),
            tungstenite::Error::Protocol(e) => Self::Protocol(e.into()),
            tungstenite::Error::Capacity(e) => Self::Capacity(e.into()),
            tungstenite::Error::WriteBufferFull(_) => Self::Capacity(SpaceError::SendQueueFull),
            tungstenite::Error::Url(e) => Self::Url(e),
            tungstenite::Error::Http(response) => Self::Http(response),
            tungstenite::Error::HttpFormat(e) => Self::HttpFormat(e),
            tungstenite::Error::Utf8 => Self::Other("UTF-8 error"),
            tungstenite::Error::AttackAttempt => Self::Other("attack attempt"),
            tungstenite::Error::Tls(_) => unreachable!("all TLS is handled below tungstenite"),
        }
    }
}

#[derive_where(Clone)]
#[derive(Debug)]
pub struct WebSocketClientWriter<S, E> {
    ws_sink: Arc<Mutex<SplitSink<WebSocketStream<S>, Message>>>,
    service_cancellation: CancellationToken,
    error_type: PhantomData<E>,
}

impl<S: AsyncDuplexStream, E> WebSocketClientWriter<S, E>
where
    WebSocketServiceError: Into<E>,
{
    pub async fn send(&self, message: impl Into<Message>) -> Result<(), E> {
        run_and_update_status(&self.service_cancellation, || {
            async {
                let mut guard = self.ws_sink.lock().await;
                guard.send(message.into()).await?;
                guard.flush().await?;
                Ok(())
            }
            .map_err(|e: tungstenite::Error| WebSocketServiceError::from(e).into())
        })
        .await
    }
}

#[derive(Debug)]
pub struct WebSocketClientReader<S, E> {
    ws_stream: SplitStream<WebSocketStream<S>>,
    ws_writer: WebSocketClientWriter<S, E>,
    service_cancellation: CancellationToken,
    keep_alive_interval: Duration,
    max_idle_time: Duration,
    last_frame_received: Instant,
    last_keepalive_sent: Instant,
}

impl<S: AsyncDuplexStream, E> WebSocketClientReader<S, E>
where
    WebSocketServiceError: Into<E>,
{
    pub async fn next(&mut self) -> Result<NextOrClose<TextOrBinary>, E> {
        enum Event {
            Message(Option<Result<Message, tungstenite::Error>>),
            SendKeepAlive,
            IdleTimeout,
            StopService,
        }
        run_and_update_status(&self.service_cancellation, || async {
            loop {
                // first, waiting for the next lifecycle action
                let next_ping_time = self.last_keepalive_sent + self.keep_alive_interval;
                let idle_timeout_time = self.last_frame_received + self.max_idle_time;
                let maybe_message = match tokio::select! {
                    maybe_message = self.ws_stream.next() => Event::Message(maybe_message),
                    _ = tokio::time::sleep_until(next_ping_time) => Event::SendKeepAlive,
                    _ = tokio::time::sleep_until(idle_timeout_time) => Event::IdleTimeout,
                    _ = self.service_cancellation.cancelled() => Event::StopService,
                } {
                    Event::SendKeepAlive => {
                        self.ws_writer.send(Message::Ping(vec![])).await?;
                        self.last_keepalive_sent = Instant::now();
                        continue;
                    }
                    Event::Message(maybe_message) => maybe_message,
                    Event::StopService => {
                        log::info!("service was stopped");
                        return Err(WebSocketServiceError::ChannelClosed.into());
                    }
                    Event::IdleTimeout => {
                        log::warn!("channel was idle for {}s", self.max_idle_time.as_secs());
                        return Err(WebSocketServiceError::ChannelIdleTooLong.into());
                    }
                };
                // now checking if whatever we've read from the stream is a message
                let message = match maybe_message {
                    None | Some(Err(tungstenite::Error::ConnectionClosed)) => {
                        log::warn!("websocket connection was unexpectedly closed");
                        return Ok(NextOrClose::Close(None));
                    }
                    Some(Err(e)) => {
                        log::trace!("websocket error: {e}");
                        return Err(WebSocketServiceError::from(e).into());
                    }
                    Some(Ok(message)) => message,
                };
                // finally, looking at the type of the message
                self.last_frame_received = Instant::now();
                match message {
                    Message::Text(t) => return Ok(NextOrClose::Next(t.into())),
                    Message::Binary(b) => return Ok(NextOrClose::Next(b.into())),
                    Message::Ping(_) | Message::Pong(_) => continue,
                    Message::Close(close_frame) => {
                        self.service_cancellation
                            .cancel(CancellationReason::RemoteClose);
                        return Ok(NextOrClose::Close(close_frame));
                    }
                    Message::Frame(_) => unreachable!("only for sending"),
                }
            }
        })
        .await
    }
}

async fn run_and_update_status<T, F, Ft, E>(
    service_status: &CancellationToken,
    f: F,
) -> Result<T, E>
where
    WebSocketServiceError: Into<E>,
    F: FnOnce() -> Ft,
    Ft: Future<Output = Result<T, E>>,
{
    if service_status.is_cancelled() {
        return Err(WebSocketServiceError::ChannelClosed.into());
    }
    let result = f().await;
    if result.is_err() {
        service_status.cancel(CancellationReason::ServiceError);
    }
    result
}

#[derive(Debug, derive_more::From)]
#[cfg_attr(any(test, feature = "test-util"), derive(Clone, Eq, PartialEq))]
pub enum TextOrBinary {
    #[from(String, &str)]
    Text(String),
    #[from(Vec<u8>)]
    Binary(Vec<u8>),
}

impl From<TextOrBinary> for Message {
    fn from(value: TextOrBinary) -> Self {
        match value {
            TextOrBinary::Binary(b) => Self::Binary(b),
            TextOrBinary::Text(t) => Self::Text(t),
        }
    }
}

pub type DefaultStream = tokio_boring_signal::SslStream<tokio::net::TcpStream>;

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(any(test, feature = "test-util"), derive(Debug))]
pub enum NextOrClose<T> {
    Next(T),
    Close(Option<CloseFrame<'static>>),
}

impl<T> NextOrClose<T> {
    pub fn next_or<E>(self, failure: E) -> Result<T, E> {
        match self {
            Self::Close(_) => Err(failure),
            Self::Next(t) => Ok(t),
        }
    }

    pub fn next_or_else<E>(
        self,
        on_close: impl FnOnce(Option<CloseFrame<'static>>) -> E,
    ) -> Result<T, E> {
        match self {
            Self::Next(t) => Ok(t),
            Self::Close(close) => Err(on_close(close)),
        }
    }
}

impl<S: Connection + tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> Connection
    for tokio_tungstenite::WebSocketStream<S>
{
    fn transport_info(&self) -> crate::TransportInfo {
        self.get_ref().transport_info()
    }
}

/// Test utilities related to websockets.
#[cfg(any(test, feature = "test-util"))]
pub mod testutil {
    use tokio::io::DuplexStream;
    use tokio_tungstenite::WebSocketStream;
    use tungstenite::protocol::WebSocketConfig;

    use super::*;

    pub async fn fake_websocket() -> (WebSocketStream<DuplexStream>, WebSocketStream<DuplexStream>)
    {
        let (client, server) = tokio::io::duplex(1024);
        let client_future = Stateless.connect_over(
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
                    front_name: None,
                },
            ),
            "test".into(),
        );
        let server_future = tokio_tungstenite::accept_async(server);
        let (client_res, server_res) = tokio::join!(client_future, server_future);
        let StreamWithResponseHeaders {
            stream: client_stream,
            response_headers: _,
        } = client_res.unwrap();
        let server_stream = server_res.unwrap();
        (server_stream, client_stream)
    }
}

#[cfg(test)]
mod test {

    use super::testutil::*;
    use super::*;

    #[tokio::test]
    async fn websocket_client_sends_pong_on_server_ping() {
        let (mut server, mut client) = fake_websocket().await;
        // starting a client that only listens to the incoming messages,
        // but not sending any responses on its own
        let _client = tokio::spawn(async move { while let Some(Ok(_)) = client.next().await {} });
        server.send(Message::Ping(vec![])).await.unwrap();
        let response = server
            .next()
            .await
            .expect("some result")
            .expect("ok result");
        assert_eq!(response, Message::Pong(vec![]));
    }
}
