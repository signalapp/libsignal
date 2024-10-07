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
use attest::client_connection::ClientConnection;
use attest::enclave;
use derive_where::derive_where;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt, TryFutureExt};
use http::uri::PathAndQuery;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tokio_tungstenite::WebSocketStream;
use tungstenite::handshake::client::generate_key;
use tungstenite::protocol::CloseFrame;
use tungstenite::{http, Message};

use crate::errors::LogSafeDisplay;
use crate::host::Host;
use crate::service::{CancellationReason, CancellationToken, ServiceConnector};
use crate::utils::timeout;
use crate::ws::error::{HttpFormatError, ProtocolError, SpaceError};
use crate::{
    Alpn, AsyncDuplexStream, ConnectionInfo, ConnectionParams, StreamAndInfo, TransportConnector,
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

/// [`ServiceConnector`] for services that wrap a websocket connection.
#[derive_where(Clone; T)]
pub struct WebSocketClientConnector<T, E> {
    transport_connector: T,
    cfg: WebSocketConfig,
    service_error_type: PhantomData<E>,
}

impl<T: TransportConnector, E> WebSocketClientConnector<T, E> {
    pub fn new(transport_connector: T, cfg: WebSocketConfig) -> Self {
        Self {
            transport_connector,
            cfg,
            service_error_type: PhantomData,
        }
    }
}

/// A simplified version of [`tungstenite::Error`] that supports [`LogSafeDisplay`].
#[derive(Debug, thiserror::Error)]
pub enum WebSocketServiceError {
    ChannelClosed,
    ChannelIdleTooLong,
    Io(std::io::Error),
    Protocol(tungstenite::error::ProtocolError),
    Capacity(SpaceError),
    Http(http::Response<Option<Vec<u8>>>),
    HttpFormat(http::Error),
    Url(tungstenite::error::UrlError),
    Other(&'static str),
}

impl LogSafeDisplay for WebSocketServiceError {}
impl Display for WebSocketServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebSocketServiceError::ChannelClosed => write!(f, "channel already closed"),
            WebSocketServiceError::ChannelIdleTooLong => write!(f, "channel was idle for too long"),
            WebSocketServiceError::Io(e) => write!(f, "IO error: {}", e.kind()),
            WebSocketServiceError::Protocol(p) => {
                write!(f, "websocket protocol: {}", ProtocolError::from(p.clone()))
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
            tungstenite::Error::Protocol(e) => Self::Protocol(e),
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
    type Service = WebSocketClient<T::Stream, E>;
    type Channel = (WebSocketStream<T::Stream>, ConnectionInfo);
    type ConnectError = WebSocketConnectError;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::ConnectError> {
        let connect_future = connect_websocket(
            connection_params,
            self.cfg.endpoint.clone(),
            self.cfg.ws_config,
            &self.transport_connector,
        );
        timeout(
            self.cfg.max_connection_time,
            WebSocketConnectError::Timeout,
            connect_future,
        )
        .await
        .map_err(Into::into)
    }

    fn start_service(&self, channel: Self::Channel) -> (Self::Service, CancellationToken) {
        start_ws_service(
            channel.0,
            channel.1,
            self.cfg.keep_alive_interval,
            self.cfg.max_idle_time,
        )
    }
}

fn start_ws_service<S: AsyncDuplexStream, E>(
    channel: WebSocketStream<S>,
    connection_info: ConnectionInfo,
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
            connection_info,
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
) -> Result<(WebSocketStream<T::Stream>, ConnectionInfo), WebSocketConnectError> {
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
    .await
    .map_err(|e| {
        // Because of the `await`, it's possible some time has already elapsed since the response
        // came in, but this is the first chance we have to process it. A late timestamp means a
        // more conservative retry period, that's all.
        handle_ws_error(connection_params, e, Instant::now())
    })?;

    Ok((ws_stream, remote_address))
}

fn handle_ws_error(
    connection_params: &ConnectionParams,
    error: tungstenite::Error,
    received_at: Instant,
) -> WebSocketConnectError {
    match error {
        tungstenite::Error::Http(response)
            if connection_params
                .connection_confirmation_header
                .as_ref()
                .map(|header| response.headers().contains_key(header))
                .unwrap_or(true) =>
        {
            // Promote any HTTP error to an explicit rejection if
            // - the confirmation header is present in the response, or
            // - there's no header to check
            WebSocketConnectError::RejectedByServer {
                response,
                received_at,
            }
        }
        e => WebSocketConnectError::WebSocketError(e),
    }
}

#[derive(Debug)]
#[cfg_attr(any(test, feature = "test-util"), derive(Clone, Eq, PartialEq))]
pub enum TextOrBinary {
    Text(String),
    Binary(Vec<u8>),
}

impl From<String> for TextOrBinary {
    fn from(value: String) -> Self {
        Self::Text(value)
    }
}

impl From<Vec<u8>> for TextOrBinary {
    fn from(value: Vec<u8>) -> Self {
        Self::Binary(value)
    }
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
    pub connection_info: ConnectionInfo,
}

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

    #[cfg(any(test, feature = "test-util"))]
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

#[derive(Debug)]
pub enum AttestedConnectionError {
    Protocol,
    ClientConnection(attest::client_connection::Error),
    Attestation(attest::enclave::Error),
    WebSocket(WebSocketServiceError),
}

impl From<enclave::Error> for AttestedConnectionError {
    fn from(value: attest::enclave::Error) -> Self {
        Self::Attestation(value)
    }
}

impl From<WebSocketServiceError> for AttestedConnectionError {
    fn from(value: WebSocketServiceError) -> Self {
        Self::WebSocket(value)
    }
}

impl From<attest::client_connection::Error> for AttestedConnectionError {
    fn from(value: attest::client_connection::Error) -> Self {
        Self::ClientConnection(value)
    }
}

pub type DefaultStream = tokio_boring_signal::SslStream<tokio::net::TcpStream>;

/// Encrypted connection to an attested host.
#[derive(Debug)]
pub struct AttestedConnection<S> {
    websocket: WebSocketClient<S, WebSocketServiceError>,
    client_connection: ClientConnection,
}

impl<S> AttestedConnection<S> {
    pub fn remote_address(&self) -> &Host<Arc<str>> {
        &self.websocket.connection_info.address
    }

    pub fn handshake_hash(&self) -> &[u8] {
        &self.client_connection.handshake_hash
    }
}

impl<S> AsMut<AttestedConnection<S>> for AttestedConnection<S> {
    fn as_mut(&mut self) -> &mut AttestedConnection<S> {
        self
    }
}

pub async fn run_attested_interaction<
    C: AsMut<AttestedConnection<S>>,
    B: AsRef<[u8]>,
    S: AsyncDuplexStream,
>(
    connection: &mut C,
    bytes: B,
) -> Result<NextOrClose<Vec<u8>>, AttestedConnectionError> {
    let connection = connection.as_mut();
    connection.send_bytes(bytes).await?;
    connection.receive_bytes().await
}

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

impl<S> AttestedConnection<S>
where
    S: AsyncDuplexStream,
{
    /// Connect to remote host and verify remote attestation.
    pub async fn connect(
        mut websocket: WebSocketClient<S, WebSocketServiceError>,
        new_handshake: impl FnOnce(&[u8]) -> enclave::Result<enclave::Handshake>,
    ) -> Result<Self, AttestedConnectionError> {
        let client_connection = authenticate(&mut websocket, new_handshake).await?;

        Ok(Self {
            websocket,
            client_connection,
        })
    }

    pub async fn send(
        &mut self,
        request: impl prost::Message,
    ) -> Result<(), AttestedConnectionError> {
        let request = request.encode_to_vec();
        self.send_bytes(request).await
    }

    pub async fn send_bytes<B: AsRef<[u8]>>(
        &mut self,
        bytes: B,
    ) -> Result<(), AttestedConnectionError> {
        let request = self.client_connection.send(bytes.as_ref())?;
        self.websocket
            .send(request.into())
            .await
            .map_err(Into::into)
    }

    pub async fn receive<T: prost::Message + Default>(
        &mut self,
    ) -> Result<NextOrClose<T>, AttestedConnectionError> {
        let received = match self.receive_bytes().await? {
            NextOrClose::Close(frame) => return Ok(NextOrClose::Close(frame)),
            NextOrClose::Next(b) => b,
        };
        T::decode(received.as_ref())
            .map_err(|_| AttestedConnectionError::Protocol)
            .map(NextOrClose::Next)
    }

    pub async fn receive_bytes(&mut self) -> Result<NextOrClose<Vec<u8>>, AttestedConnectionError> {
        let received = self.websocket.receive().await?;
        let received = match received {
            NextOrClose::Close(frame) => return Ok(NextOrClose::Close(frame)),
            NextOrClose::Next(t) => t.try_into_binary()?,
        };
        self.client_connection
            .recv(&received)
            .map(NextOrClose::Next)
            .map_err(Into::into)
    }
}

impl TextOrBinary {
    fn try_into_binary(self) -> Result<Vec<u8>, AttestedConnectionError> {
        match self {
            TextOrBinary::Text(_) => Err(AttestedConnectionError::Protocol),
            TextOrBinary::Binary(b) => Ok(b),
        }
    }
}

async fn authenticate<S: AsyncDuplexStream>(
    websocket: &mut WebSocketClient<S, WebSocketServiceError>,
    new_handshake: impl FnOnce(&[u8]) -> enclave::Result<enclave::Handshake>,
) -> Result<ClientConnection, AttestedConnectionError> {
    let attestation_msg = websocket
        .receive()
        .await?
        .next_or(WebSocketServiceError::ChannelClosed)?
        .try_into_binary()?;
    let handshake = new_handshake(attestation_msg.as_ref())?;

    websocket
        .send(Vec::from(handshake.initial_request()).into())
        .await?;

    let initial_response = websocket
        .receive()
        .await?
        .next_or(WebSocketServiceError::ChannelClosed)?
        .try_into_binary()?;

    Ok(handshake.complete(&initial_response)?)
}

/// Test utilities related to websockets.
#[cfg(any(test, feature = "test-util"))]
pub mod testutil {
    use tokio::io::DuplexStream;
    use tokio_tungstenite::WebSocketStream;

    use super::*;
    use crate::timeouts::{WS_KEEP_ALIVE_INTERVAL, WS_MAX_IDLE_INTERVAL};
    use crate::{AsyncDuplexStream, DnsSource, RouteType};

    pub async fn fake_websocket() -> (WebSocketStream<DuplexStream>, WebSocketStream<DuplexStream>)
    {
        let (client, server) = tokio::io::duplex(1024);
        let req = url::Url::parse("ws://localhost:8080/").unwrap();
        let client_future = tokio_tungstenite::client_async(req, client);
        let server_future = tokio_tungstenite::accept_async(server);
        let (client_res, server_res) = tokio::join!(client_future, server_future);
        let (client_stream, _) = client_res.unwrap();
        let server_stream = server_res.unwrap();
        (server_stream, client_stream)
    }

    pub fn mock_connection_info() -> ConnectionInfo {
        ConnectionInfo {
            route_type: RouteType::Test,
            dns_source: DnsSource::Test,
            address: Host::Domain("localhost".into()),
        }
    }

    pub fn websocket_test_client<S: AsyncDuplexStream>(
        channel: WebSocketStream<S>,
    ) -> WebSocketClient<S, WebSocketServiceError> {
        start_ws_service(
            channel,
            mock_connection_info(),
            WS_KEEP_ALIVE_INTERVAL,
            WS_MAX_IDLE_INTERVAL,
        )
        .0
    }

    impl<S: AsyncDuplexStream, E> WebSocketClient<S, E> {
        pub fn new_fake(channel: WebSocketStream<S>, connection_info: ConnectionInfo) -> Self {
            const VERY_LARGE_TIMEOUT: Duration = Duration::from_secs(u32::MAX as u64);
            let (client, _service_status) = start_ws_service(
                channel,
                connection_info,
                VERY_LARGE_TIMEOUT,
                VERY_LARGE_TIMEOUT,
            );
            client
        }
    }

    pub const FAKE_ATTESTATION: &[u8] =
        include_bytes!("../../../attest/tests/data/svr2handshakestart.data");

    /// Response to an incoming frame.
    ///
    /// Zero or one frames to reply with followed by an optional close.
    #[derive(Default)]
    pub struct AttestedServerOutput {
        pub message: Option<Vec<u8>>,
        pub close_after: Option<Option<CloseFrame<'static>>>,
    }

    impl AttestedServerOutput {
        pub fn message(contents: Vec<u8>) -> Self {
            Self {
                message: Some(contents),
                ..Default::default()
            }
        }

        pub fn close(frame: Option<CloseFrame<'static>>) -> Self {
            Self {
                close_after: Some(frame),
                ..Default::default()
            }
        }
    }

    impl<T: Debug> NextOrClose<T> {
        pub(crate) fn unwrap_next(self) -> T
        where
            T: Debug,
        {
            match self {
                Self::Next(t) => t,
                s @ Self::Close(_) => panic!("unwrap called on {s:?}"),
            }
        }
    }

    /// Runs a fake SGX server that sets up a session and then responds to requests.
    ///
    /// Produces a future that, when polled, runs the server side of an attested
    /// websocket connection. The provided callback is executed for each
    /// incoming event, and the returned value is sent to the peer. If the
    /// callback returns an [`AttestedServerOutput`] with `close_after:
    /// Some(_)`, the connection is terminated and this future resolves.
    pub async fn run_attested_server(
        websocket: WebSocketStream<impl AsyncDuplexStream>,
        private_key: impl AsRef<[u8]>,
        mut on_message: impl FnMut(NextOrClose<Vec<u8>>) -> AttestedServerOutput,
    ) {
        let mut websocket = websocket_test_client(websocket);
        // Start the server with a known private key (K of NK).
        let mut server_hs =
            snow::Builder::new(attest::client_connection::NOISE_PATTERN.parse().unwrap())
                .local_private_key(private_key.as_ref())
                .build_responder()
                .unwrap();

        // The server first sends over its attestation message.
        websocket
            .send(Vec::from(FAKE_ATTESTATION).into())
            .await
            .unwrap();

        // Wait for the handshake from the client.
        let incoming = websocket
            .receive()
            .await
            .unwrap()
            .unwrap_next()
            .try_into_binary()
            .unwrap();
        assert_eq!(server_hs.read_message(&incoming, &mut []).unwrap(), 0);

        let mut message = vec![0u8; 48];
        let write_size = server_hs.write_message(&[], &mut message).unwrap();

        assert_eq!(write_size, 48);
        assert!(server_hs.is_handshake_finished());

        websocket.send(message.into()).await.unwrap();

        let mut server_transport = server_hs.into_transport_mode().unwrap();

        while let Ok(incoming) = websocket.receive().await {
            let received = match incoming {
                NextOrClose::Close(close) => NextOrClose::Close(close),
                NextOrClose::Next(incoming) => {
                    let incoming = incoming.try_into_binary().unwrap();
                    let mut payload = vec![0; incoming.len()];
                    let read = server_transport
                        .read_message(&incoming, &mut payload)
                        .unwrap();
                    payload.truncate(read);

                    NextOrClose::Next(payload)
                }
            };

            let AttestedServerOutput {
                close_after,
                message,
            } = on_message(received);

            if let Some(payload) = message {
                let mut outgoing = vec![0; payload.len() + 16 /* snow tag len */];
                let written = server_transport
                    .write_message(&payload, &mut outgoing)
                    .unwrap();
                outgoing.truncate(written);
                websocket.send(outgoing.into()).await.unwrap();
            }

            if let Some(close) = close_after {
                websocket.close(close).await.unwrap();
                return;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use futures_util::{pin_mut, poll};
    use nonzero_ext::nonzero;
    use test_case::test_matrix;

    use super::testutil::*;
    use super::*;
    use crate::certs::RootCertificates;
    use crate::{HttpRequestDecoratorSeq, RouteType, TransportConnectionParams};

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

    /// Runs a fake SGX server that sets up a session and then echos back
    /// incoming messages.
    async fn run_attested_echo_server(
        websocket: WebSocketStream<impl AsyncDuplexStream>,
        private_key: impl AsRef<[u8]>,
    ) {
        run_attested_server(websocket, private_key, |message| {
            // Just echo any incoming message back.
            match message {
                NextOrClose::Next(message) => AttestedServerOutput::message(message),
                NextOrClose::Close(close) => AttestedServerOutput::close(close),
            }
        })
        .await
    }

    const ECHO_BYTES: &[u8] = b"two nibbles to a byte";

    #[tokio::test]
    async fn attested_connection_happy_path() {
        // Start the server with a known private key (K of NK).
        let (server, client) = fake_websocket().await;
        tokio::task::spawn(run_attested_echo_server(
            server,
            attest::sgx_session::testutil::private_key(),
        ));

        let mut connection =
            AttestedConnection::connect(websocket_test_client(client), |fake_attestation| {
                assert_eq!(fake_attestation, FAKE_ATTESTATION);
                attest::sgx_session::testutil::handshake_from_tests_data()
            })
            .await
            .unwrap();

        connection.send(Vec::from(ECHO_BYTES)).await.unwrap();
        let response: Vec<u8> = connection.receive().await.unwrap().unwrap_next();
        assert_eq!(&response, ECHO_BYTES);
    }

    #[tokio::test]
    async fn attested_connection_invalid_handshake() {
        // Start the server with a known private key (K of NK).
        let (server, client) = fake_websocket().await;
        tokio::task::spawn(run_attested_echo_server(
            server,
            attest::sgx_session::testutil::private_key(),
        ));

        fn fail_to_handshake(_attestation: &[u8]) -> attest::enclave::Result<enclave::Handshake> {
            Err(attest::enclave::Error::AttestationDataError {
                reason: "invalid".to_string(),
            })
        }

        assert_matches!(
            AttestedConnection::connect(websocket_test_client(client), fail_to_handshake).await,
            Err(_)
        );
    }

    #[tokio::test]
    async fn attested_connection_invalid_decode() {
        // Start the server with a known private key (K of NK).
        let (server, client) = fake_websocket().await;
        tokio::task::spawn(run_attested_echo_server(
            server,
            attest::sgx_session::testutil::private_key(),
        ));

        let mut connection =
            AttestedConnection::connect(websocket_test_client(client), |fake_attestation| {
                assert_eq!(fake_attestation, FAKE_ATTESTATION);
                attest::sgx_session::testutil::handshake_from_tests_data()
            })
            .await
            .unwrap();

        connection.send(Vec::from(ECHO_BYTES)).await.unwrap();
        // Decoding a vec as a 32-bit float shouldn't work.
        assert_matches!(
            connection.receive::<f32>().await.expect_err("wrong type"),
            AttestedConnectionError::Protocol
        );
    }

    fn example_connection_params(hostname: &str) -> ConnectionParams {
        let hostname = hostname.into();
        ConnectionParams {
            route_type: RouteType::Test,
            transport: TransportConnectionParams {
                sni: Arc::clone(&hostname),
                tcp_host: Host::Domain(Arc::clone(&hostname)),
                port: nonzero!(443u16),
                certs: RootCertificates::Native,
            },
            http_host: hostname,
            http_request_decorator: HttpRequestDecoratorSeq::default(),
            connection_confirmation_header: None,
        }
    }

    #[test_matrix([None, Some("x-pinky-promise")])]
    fn classify_errors(confirmation_header: Option<&'static str>) {
        let now = Instant::now();
        let connection_params = example_connection_params("example.signal.org");
        let connection_params = if let Some(header) = confirmation_header {
            connection_params.with_confirmation_header(http::HeaderName::from_static(header))
        } else {
            connection_params
        };

        let non_http_error = handle_ws_error(
            &connection_params,
            tungstenite::Error::Io(std::io::ErrorKind::BrokenPipe.into()),
            now,
        );
        assert_matches!(
            non_http_error,
            WebSocketConnectError::WebSocketError(tungstenite::Error::Io(_))
        );

        let mut response_4xx = http::Response::new(None);
        *response_4xx.status_mut() = http::StatusCode::BAD_REQUEST;

        let http_4xx_error = handle_ws_error(
            &connection_params,
            tungstenite::Error::Http(response_4xx.clone()),
            now,
        );
        if connection_params.connection_confirmation_header.is_some() {
            assert_matches!(
                http_4xx_error,
                WebSocketConnectError::WebSocketError(tungstenite::Error::Http(_))
            );
        } else {
            assert_matches!(
                http_4xx_error,
                WebSocketConnectError::RejectedByServer { response: _, received_at } if received_at == now
            );
        }

        if let Some(header) = &connection_params.connection_confirmation_header {
            response_4xx
                .headers_mut()
                .append(header, http::HeaderValue::from_static("1"));

            let error_with_header = handle_ws_error(
                &connection_params,
                tungstenite::Error::Http(response_4xx.clone()),
                now,
            );
            assert_matches!(
                error_with_header,
                WebSocketConnectError::RejectedByServer { response: _, received_at } if received_at == now
            );
        }
    }
}
