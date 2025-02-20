//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::{Debug, Display};
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use derive_where::derive_where;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{Sink, SinkExt as _, Stream, StreamExt, TryFutureExt};
use http::uri::PathAndQuery;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tokio_tungstenite::WebSocketStream;
use tungstenite::handshake::client::generate_key;
use tungstenite::protocol::CloseFrame;
use tungstenite::{http, Message};

use crate::errors::LogSafeDisplay;
use crate::route::{Connector, HttpRouteFragment, WebSocketRouteFragment};
use crate::service::{CancellationReason, CancellationToken, ServiceConnector};
use crate::utils::timeout;
use crate::ws::error::{HttpFormatError, ProtocolError, SpaceError};
use crate::{
    Alpn, AsyncDuplexStream, Connection, ConnectionParams, HttpRequestDecorator,
    ServiceConnectionInfo, StreamAndInfo, TransportConnector,
};

pub mod error;
pub use error::{Error, WebSocketConnectError};

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

/// [`ServiceConnector`] for services that wrap a websocket connection.
#[derive_where(Clone; T)]
pub struct WebSocketClientConnector<T, E> {
    service_connector: WebSocketStreamConnector<T>,
    keep_alive_interval: Duration,
    max_idle_time: Duration,
    service_error_type: PhantomData<E>,
}

impl<T: TransportConnector, E> WebSocketClientConnector<T, E> {
    pub fn new(transport_connector: T, cfg: WebSocketConfig) -> Self {
        let WebSocketConfig {
            ws_config,
            endpoint,
            max_connection_time,
            keep_alive_interval,
            max_idle_time,
        } = cfg;
        Self {
            service_connector: WebSocketStreamConnector::new(
                transport_connector,
                WebSocketRouteFragment {
                    headers: Default::default(),
                    ws_config,
                    endpoint,
                },
                max_connection_time,
            ),
            keep_alive_interval,
            max_idle_time,
            service_error_type: PhantomData,
        }
    }
}

/// [`ServiceConnector`] that produces a [`WebSocketStream`] as its service.
#[derive(Clone)]
pub struct WebSocketStreamConnector<T> {
    transport_connector: T,
    fragment: WebSocketRouteFragment,
    max_connection_time: Duration,
}

impl<T: TransportConnector> WebSocketStreamConnector<T> {
    pub fn new(
        transport_connector: T,
        fragment: WebSocketRouteFragment,
        max_connection_time: Duration,
    ) -> Self {
        Self {
            transport_connector,
            fragment,
            max_connection_time,
        }
    }
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
    type Connection = tokio_tungstenite::WebSocketStream<Inner>;

    type Error = tungstenite::Error;

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
        };

        async move {
            let uri = http::uri::Builder::new()
                .path_and_query(uri_path?)
                .authority(&*host_header)
                .scheme("wss")
                .build()?;

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
                .body(())?;

            let (stream, _response) =
                tokio_tungstenite::client_async_with_config(request, inner, Some(ws_config))
                    .await?;

            Ok(stream)
        }
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

#[async_trait]
impl<T, E> ServiceConnector for WebSocketClientConnector<T, E>
where
    T: TransportConnector,
    E: Send + Sync,
    WebSocketServiceError: Into<E>,
{
    type Service = (WebSocketClient<T::Stream, E>, ServiceConnectionInfo);
    type Channel = (WebSocketStream<T::Stream>, ServiceConnectionInfo);
    type ConnectError = WebSocketConnectError;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::ConnectError> {
        self.service_connector
            .connect_channel(connection_params)
            .await
    }

    fn start_service(&self, channel: Self::Channel) -> (Self::Service, CancellationToken) {
        let (service, token) =
            start_ws_service(channel.0, self.keep_alive_interval, self.max_idle_time);
        ((service, channel.1), token)
    }
}

#[async_trait]
impl<T> ServiceConnector for WebSocketStreamConnector<T>
where
    T: TransportConnector,
{
    type Service = (WebSocketStream<T::Stream>, ServiceConnectionInfo);
    type Channel = (WebSocketStream<T::Stream>, ServiceConnectionInfo);
    type ConnectError = WebSocketConnectError;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::ConnectError> {
        let WebSocketRouteFragment {
            ws_config,
            endpoint,
            headers,
        } = &self.fragment;
        let connection_params = connection_params
            .clone()
            .with_decorator(HttpRequestDecorator::Headers(headers.clone()));
        let connect_future = connect_websocket(
            &connection_params,
            endpoint.clone(),
            *ws_config,
            &self.transport_connector,
        );
        timeout(
            self.max_connection_time,
            WebSocketConnectError::Timeout,
            connect_future,
        )
        .await
        .map_err(Into::into)
    }

    fn start_service(&self, channel: Self::Channel) -> (Self::Service, CancellationToken) {
        (channel, CancellationToken::new())
    }
}

fn start_ws_service<S: AsyncDuplexStream, E>(
    channel: WebSocketStream<S>,
    keep_alive_interval: Duration,
    max_idle_time: Duration,
) -> (WebSocketClient<S, E>, CancellationToken) {
    let service_cancellation = CancellationToken::new();
    let (ws_sink, ws_stream) = channel.split();
    let ws_client_writer = WebSocketClientWriter {
        ws_sink: Arc::new(Mutex::new(ws_sink)),
        service_cancellation: service_cancellation.clone(),
        error_type: Default::default(),
    };
    let ws_client_reader = WebSocketClientReader {
        ws_stream,
        keep_alive_interval,
        max_idle_time,
        ws_writer: ws_client_writer.clone(),
        service_cancellation: service_cancellation.clone(),
        last_frame_received: Instant::now(),
        last_keepalive_sent: Instant::now(),
    };
    (
        WebSocketClient {
            ws_client_writer,
            ws_client_reader,
        },
        service_cancellation,
    )
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
    result.map_err(Into::into)
}

async fn connect_websocket<T: TransportConnector>(
    connection_params: &ConnectionParams,
    endpoint: PathAndQuery,
    ws_config: tungstenite::protocol::WebSocketConfig,
    transport_connector: &T,
) -> Result<(WebSocketStream<T::Stream>, ServiceConnectionInfo), WebSocketConnectError> {
    let StreamAndInfo(ssl_stream, remote_address) = transport_connector
        .connect(&connection_params.transport, Alpn::Http1_1)
        .await?;

    // we need to explicitly create upgrade request
    // because request decorators require a request `Builder`
    let request_builder = http::Request::builder()
        .method("GET")
        .header(
            http::header::HOST,
            http::HeaderValue::from_str(&connection_params.http_host)
                .expect("valid `HOST` header value"),
        )
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .uri(
            http::uri::Builder::new()
                .authority(connection_params.http_host.to_string())
                .path_and_query(endpoint)
                .scheme("wss")
                .build()
                .unwrap(),
        );

    let request_builder = connection_params
        .http_request_decorator
        .decorate_request(request_builder);

    let (ws_stream, _response) = tokio_tungstenite::client_async_with_config(
        request_builder.body(()).expect("can get request body"),
        ssl_stream,
        Some(ws_config),
    )
    .await?;

    Ok((ws_stream, remote_address))
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

/// Wrapper for a websocket that can be used to send [`TextOrBinary`] messages.
#[derive(Debug)]
pub struct WebSocketClient<S, E> {
    pub ws_client_writer: WebSocketClientWriter<S, E>,
    pub ws_client_reader: WebSocketClientReader<S, E>,
}

#[cfg(any(test, feature = "test-util"))]
impl<S: AsyncDuplexStream, E> WebSocketClient<S, E>
where
    WebSocketServiceError: Into<E>,
{
    /// Sends a request on the connection.
    ///
    /// An error is returned if the send fails.
    pub(crate) async fn send(&mut self, item: TextOrBinary) -> Result<(), E> {
        self.ws_client_writer.send(item).await
    }

    pub(crate) async fn close(self, close: Option<CloseFrame<'static>>) -> Result<(), E> {
        self.ws_client_writer.send(Message::Close(close)).await
    }

    /// Receives a message on the connection.
    ///
    /// Returns the next text or binary message received on the wrapped socket.
    /// If the next response received is a [`Message::Close`], returns `None`.
    pub(crate) async fn receive(&mut self) -> Result<NextOrClose<TextOrBinary>, E> {
        self.ws_client_reader.next().await
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
    use crate::timeouts::{WS_KEEP_ALIVE_INTERVAL, WS_MAX_IDLE_INTERVAL};
    use crate::AsyncDuplexStream;

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
        let client_stream = client_res.unwrap();
        let server_stream = server_res.unwrap();
        (server_stream, client_stream)
    }

    pub fn websocket_test_client<S: AsyncDuplexStream>(
        channel: WebSocketStream<S>,
    ) -> WebSocketClient<S, WebSocketServiceError> {
        start_ws_service(channel, WS_KEEP_ALIVE_INTERVAL, WS_MAX_IDLE_INTERVAL).0
    }

    impl<S: AsyncDuplexStream, E> WebSocketClient<S, E> {
        pub fn new_fake(channel: WebSocketStream<S>) -> Self {
            const VERY_LARGE_TIMEOUT: Duration = Duration::from_secs(u32::MAX as u64);
            let (client, _service_status) =
                start_ws_service(channel, VERY_LARGE_TIMEOUT, VERY_LARGE_TIMEOUT);
            client
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use futures_util::{pin_mut, poll};

    use super::testutil::*;
    use super::*;

    const MESSAGE_TEXT: &str = "text";

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

    #[tokio::test]
    async fn websocket_send_receive() {
        let (mut server, client) = fake_websocket().await;

        let _echo = tokio::spawn(async move {
            while let Some(Ok(m)) = server.next().await {
                server.send(m).await.unwrap();
            }
        });

        let mut synchronous = websocket_test_client(client);
        let item = TextOrBinary::Text(MESSAGE_TEXT.into());

        synchronous.send(item.clone()).await.unwrap();
        let response = synchronous.receive().await.unwrap();
        assert_eq!(response, NextOrClose::Next(item));
    }

    #[tokio::test]
    async fn websocket_receive() {
        let (mut server, client) = fake_websocket().await;

        let mut synchronous = websocket_test_client(client);
        let receive_unsolicited = synchronous.receive();
        pin_mut!(receive_unsolicited);

        assert_matches!(poll!(&mut receive_unsolicited), std::task::Poll::Pending);

        let item = TextOrBinary::Text(MESSAGE_TEXT.into());
        server.send(item.clone().into()).await.unwrap();

        let received_item =
            assert_matches!(receive_unsolicited.await, Ok(NextOrClose::Next(item)) => item);
        assert_eq!(received_item, item);
    }

    #[tokio::test]
    async fn websocket_remote_hangs_up() {
        let (mut server, client) = fake_websocket().await;

        let send_and_receive = async move {
            let mut ws = websocket_test_client(client);
            ws.send(TextOrBinary::Text(MESSAGE_TEXT.to_string())).await
        };

        let handle = tokio::spawn(send_and_receive);

        assert_eq!(
            server.next().await.unwrap().unwrap(),
            Message::Text(MESSAGE_TEXT.to_string())
        );

        // Hang up.
        drop(server);
        assert_matches!(handle.await.expect("joined"), Ok(()));
    }
}
