//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use derive_where::derive_where;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt as _, StreamExt};
use http::uri::PathAndQuery;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tokio_tungstenite::WebSocketStream;
use tungstenite::handshake::client::generate_key;
use tungstenite::protocol::CloseFrame;
use tungstenite::{http, Message};

use crate::infra::errors::NetError;
use crate::infra::reconnect::{ServiceConnector, ServiceStatus};
use crate::infra::{AsyncDuplexStream, ConnectionParams, TransportConnector};
use crate::utils::timeout;
use attest::client_connection::ClientConnection;
use attest::enclave;

pub mod error;
pub use error::Error;

const WS_ALPN: &[u8] = b"\x08http/1.1";

#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    pub ws_config: tungstenite::protocol::WebSocketConfig,
    pub endpoint: PathAndQuery,
    pub max_connection_time: Duration,
    pub keep_alive_interval: Duration,
    pub max_idle_time: Duration,
}

#[derive(Clone)]
pub struct WebSocketClientConnector<T> {
    transport_connector: T,
    cfg: WebSocketConfig,
}

impl<T: TransportConnector> WebSocketClientConnector<T> {
    pub(crate) fn new(transport_connector: T, cfg: WebSocketConfig) -> Self {
        Self {
            transport_connector,
            cfg,
        }
    }
}

#[async_trait]
impl<T> ServiceConnector for WebSocketClientConnector<T>
where
    T: TransportConnector,
{
    type Service = WebSocketClient<T::Stream>;
    type Channel = WebSocketStream<T::Stream>;
    type Error = NetError;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::Error> {
        let connect_future = connect_websocket(
            connection_params,
            self.cfg.endpoint.clone(),
            self.cfg.ws_config,
            &self.transport_connector,
        );
        timeout(
            self.cfg.max_connection_time,
            NetError::Timeout,
            connect_future,
        )
        .await
    }

    fn start_service(&self, channel: Self::Channel) -> (Self::Service, ServiceStatus<Self::Error>) {
        start_ws_service(
            channel,
            self.cfg.keep_alive_interval,
            self.cfg.max_idle_time,
        )
    }
}

fn start_ws_service<S: AsyncDuplexStream>(
    channel: WebSocketStream<S>,
    keep_alive_interval: Duration,
    max_idle_time: Duration,
) -> (WebSocketClient<S>, ServiceStatus<NetError>) {
    let service_status = ServiceStatus::new();
    let (ws_sink, ws_stream) = channel.split();
    let ws_client_writer = WebSocketClientWriter {
        ws_sink: Arc::new(Mutex::new(ws_sink)),
        service_status: service_status.clone(),
    };
    let ws_client_reader = WebSocketClientReader {
        ws_stream,
        keep_alive_interval,
        max_idle_time,
        ws_writer: ws_client_writer.clone(),
        service_status: service_status.clone(),
        last_frame_received: Instant::now(),
        last_keepalive_sent: Instant::now(),
    };
    (
        WebSocketClient::new(ws_client_writer, ws_client_reader),
        service_status,
    )
}

#[derive_where(Clone)]
#[derive(Debug)]
pub(crate) struct WebSocketClientWriter<S> {
    ws_sink: Arc<Mutex<SplitSink<WebSocketStream<S>, Message>>>,
    service_status: ServiceStatus<NetError>,
}

impl<S: AsyncDuplexStream> WebSocketClientWriter<S> {
    pub async fn send(&self, message: impl Into<Message>) -> Result<(), NetError> {
        run_and_update_status(&self.service_status, || async {
            let mut guard = self.ws_sink.lock().await;
            guard.send(message.into()).await?;
            guard.flush().await?;
            Ok(())
        })
        .await
    }
}

#[derive(Debug)]
pub(crate) struct WebSocketClientReader<S> {
    ws_stream: SplitStream<WebSocketStream<S>>,
    ws_writer: WebSocketClientWriter<S>,
    service_status: ServiceStatus<NetError>,
    keep_alive_interval: Duration,
    max_idle_time: Duration,
    last_frame_received: Instant,
    last_keepalive_sent: Instant,
}

impl<S: AsyncDuplexStream> WebSocketClientReader<S> {
    pub async fn next(&mut self) -> Result<NextOrClose<TextOrBinary>, NetError> {
        enum Event {
            Message(Option<Result<Message, tungstenite::Error>>),
            SendKeepAlive,
            IdleTimeout,
            StopService,
        }
        run_and_update_status(&self.service_status, || async {
            loop {
                // first, waiting for the next lifecycle action
                let next_ping_time = self.last_keepalive_sent + self.keep_alive_interval;
                let idle_timeout_time = self.last_frame_received + self.max_idle_time;
                let maybe_message = match tokio::select! {
                    maybe_message = self.ws_stream.next() => Event::Message(maybe_message),
                    _ = tokio::time::sleep_until(next_ping_time) => Event::SendKeepAlive,
                    _ = tokio::time::sleep_until(idle_timeout_time) => Event::IdleTimeout,
                    _ = self.service_status.stopped() => Event::StopService,
                } {
                    Event::SendKeepAlive => {
                        self.ws_writer.send(Message::Ping(vec![])).await?;
                        self.last_keepalive_sent = Instant::now();
                        continue;
                    }
                    Event::Message(maybe_message) => maybe_message,
                    Event::StopService => {
                        log::info!("service was stopped");
                        return Err(NetError::ChannelClosed);
                    }
                    Event::IdleTimeout => {
                        log::warn!("channel was idle for {}s", self.max_idle_time.as_secs());
                        return Err(NetError::ChannelIdle);
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
                        return Err(e.into());
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
                        self.service_status.stop_service();
                        return Ok(NextOrClose::Close(close_frame));
                    }
                    Message::Frame(_) => unreachable!("only for sending"),
                }
            }
        })
        .await
    }
}

async fn run_and_update_status<T, F, Ft>(
    service_status: &ServiceStatus<NetError>,
    f: F,
) -> Result<T, NetError>
where
    F: FnOnce() -> Ft,
    Ft: Future<Output = Result<T, NetError>>,
{
    if service_status.is_stopped() {
        return Err(NetError::ChannelClosed);
    }
    let result = f().await;
    if result.is_err() {
        service_status.stop_service();
    }
    result
}

async fn connect_websocket<T: TransportConnector>(
    connection_params: &ConnectionParams,
    endpoint: PathAndQuery,
    ws_config: tungstenite::protocol::WebSocketConfig,
    transport_connector: &T,
) -> Result<WebSocketStream<T::Stream>, NetError> {
    let ssl_stream = transport_connector
        .connect(connection_params, WS_ALPN)
        .await?;

    // we need to explicitly create upgrade request
    // because request decorators require a request `Builder`
    let request_builder = http::Request::builder()
        .method("GET")
        .header(
            http::header::HOST,
            http::HeaderValue::from_str(&connection_params.host)
                .expect("valid `HOST` header value"),
        )
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .uri(
            http::uri::Builder::new()
                .authority(connection_params.host.to_string())
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

    Ok(ws_stream)
}

#[cfg_attr(test, derive(Clone, Debug, Eq, PartialEq))]
pub(crate) enum TextOrBinary {
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
pub struct WebSocketClient<S = tokio_boring::SslStream<tokio::net::TcpStream>> {
    ws_client_writer: WebSocketClientWriter<S>,
    ws_client_reader: WebSocketClientReader<S>,
}

impl<S: AsyncDuplexStream> WebSocketClient<S> {
    pub(crate) fn new(
        ws_client_writer: WebSocketClientWriter<S>,
        ws_client_reader: WebSocketClientReader<S>,
    ) -> Self {
        Self {
            ws_client_writer,
            ws_client_reader,
        }
    }

    /// Sends a request on the connection.
    ///
    /// An error is returned if the send fails.
    pub(crate) async fn send(&mut self, item: TextOrBinary) -> Result<(), NetError> {
        self.ws_client_writer.send(item).await
    }

    /// Receives a message on the connection.
    ///
    /// Returns the next text or binary message received on the wrapped socket.
    /// If the next response received is a [`Message::Close`], returns `None`.
    pub(crate) async fn receive(&mut self) -> Result<NextOrClose<TextOrBinary>, NetError> {
        self.ws_client_reader.next().await
    }

    pub(crate) fn split(self) -> (WebSocketClientWriter<S>, WebSocketClientReader<S>) {
        (self.ws_client_writer, self.ws_client_reader)
    }
}

#[derive(Debug)]
pub enum AttestedConnectionError {
    Protocol,
    ClientConnection(attest::client_connection::Error),
    Sgx(attest::enclave::Error),
    Net(NetError),
}

impl From<enclave::Error> for AttestedConnectionError {
    fn from(value: attest::enclave::Error) -> Self {
        Self::Sgx(value)
    }
}

impl From<NetError> for AttestedConnectionError {
    fn from(value: NetError) -> Self {
        Self::Net(value)
    }
}

impl From<attest::client_connection::Error> for AttestedConnectionError {
    fn from(value: attest::client_connection::Error) -> Self {
        Self::ClientConnection(value)
    }
}

pub type DefaultStream = tokio_boring::SslStream<tokio::net::TcpStream>;

/// Encrypted connection to an attested host.
#[derive(Debug)]
pub struct AttestedConnection<S = DefaultStream> {
    websocket: WebSocketClient<S>,
    client_connection: ClientConnection,
}

impl AsMut<AttestedConnection> for AttestedConnection {
    fn as_mut(&mut self) -> &mut AttestedConnection {
        self
    }
}

pub(crate) async fn run_attested_interaction<C: AsMut<AttestedConnection>, B: AsRef<[u8]>>(
    connection: &mut C,
    bytes: B,
) -> Result<NextOrClose<Vec<u8>>, AttestedConnectionError> {
    let connection = connection.as_mut();
    connection.send_bytes(bytes).await?;
    connection.receive_bytes().await
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub(crate) enum NextOrClose<T> {
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
}

impl<S> AttestedConnection<S>
where
    S: AsyncDuplexStream,
{
    /// Connect to remote host and verify remote attestation.
    pub(crate) async fn connect(
        mut websocket: WebSocketClient<S>,
        new_handshake: impl FnOnce(&[u8]) -> enclave::Result<enclave::Handshake>,
    ) -> Result<Self, AttestedConnectionError> {
        let client_connection = authenticate(&mut websocket, new_handshake).await?;

        Ok(Self {
            websocket,
            client_connection,
        })
    }

    pub(crate) async fn send(
        &mut self,
        request: impl prost::Message,
    ) -> Result<(), AttestedConnectionError> {
        let request = request.encode_to_vec();
        self.send_bytes(request).await
    }

    pub(crate) async fn send_bytes<B: AsRef<[u8]>>(
        &mut self,
        bytes: B,
    ) -> Result<(), AttestedConnectionError> {
        let request = self.client_connection.send(bytes.as_ref())?;
        self.websocket
            .send(request.into())
            .await
            .map_err(Into::into)
    }

    pub(crate) async fn receive<T: prost::Message + Default>(
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

    pub(crate) async fn receive_bytes(
        &mut self,
    ) -> Result<NextOrClose<Vec<u8>>, AttestedConnectionError> {
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
    websocket: &mut WebSocketClient<S>,
    new_handshake: impl FnOnce(&[u8]) -> enclave::Result<enclave::Handshake>,
) -> Result<ClientConnection, AttestedConnectionError> {
    let attestation_msg = websocket
        .receive()
        .await?
        .next_or(NetError::Failure)?
        .try_into_binary()?;
    let handshake = new_handshake(attestation_msg.as_ref())?;

    websocket
        .send(Vec::from(handshake.initial_request()).into())
        .await?;

    let initial_response = websocket
        .receive()
        .await?
        .next_or(NetError::Failure)?
        .try_into_binary()?;

    Ok(handshake.complete(&initial_response)?)
}

#[cfg(test)]
mod test {
    use crate::env::{WS_KEEP_ALIVE_INTERVAL, WS_MAX_IDLE_TIME};
    use assert_matches::assert_matches;
    use futures_util::{pin_mut, poll};
    use tokio::io::DuplexStream;

    use super::*;

    impl<T: Debug> NextOrClose<T> {
        fn unwrap_next(self) -> T
        where
            T: Debug,
        {
            match self {
                Self::Next(t) => t,
                s @ Self::Close(_) => panic!("unwrap called on {s:?}"),
            }
        }
    }

    const MESSAGE_TEXT: &str = "text";

    async fn fake_websocket() -> (WebSocketStream<DuplexStream>, WebSocketStream<DuplexStream>) {
        let (client, server) = tokio::io::duplex(1024);
        let req = url::Url::parse("ws://localhost:8080/").unwrap();
        let client_future = tokio_tungstenite::client_async(req, client);
        let server_future = tokio_tungstenite::accept_async(server);
        let (client_res, server_res) = tokio::join!(client_future, server_future);
        let (client_stream, _) = client_res.unwrap();
        let server_stream = server_res.unwrap();
        (server_stream, client_stream)
    }

    fn websocket_test_client<S: AsyncDuplexStream>(
        channel: WebSocketStream<S>,
    ) -> WebSocketClient<S> {
        start_ws_service(channel, WS_KEEP_ALIVE_INTERVAL, WS_MAX_IDLE_TIME).0
    }

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

        assert_eq!(poll!(&mut receive_unsolicited), std::task::Poll::Pending);

        let item = TextOrBinary::Text(MESSAGE_TEXT.into());
        server.send(item.clone().into()).await.unwrap();

        assert_eq!(receive_unsolicited.await, Ok(NextOrClose::Next(item)));
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
        assert_eq!(handle.await.expect("joined"), Ok(()));
    }

    const FAKE_ATTESTATION: &[u8] =
        include_bytes!("../../../attest/tests/data/svr2handshakestart.data");

    /// Runs a fake SGX server that sets up a session and then echos back
    /// incoming messages.
    async fn run_attested_echo_server(
        websocket: WebSocketStream<impl AsyncDuplexStream>,
        private_key: impl AsRef<[u8]>,
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

        while let NextOrClose::Next(incoming) = websocket.receive().await.unwrap() {
            let incoming = incoming.try_into_binary().unwrap();
            let mut payload = vec![0; incoming.len()];
            let read = server_transport
                .read_message(&incoming, &mut payload)
                .unwrap();
            payload.truncate(read);

            let mut outgoing = vec![0; incoming.len() * 2];
            let written = server_transport
                .write_message(&payload, &mut outgoing)
                .unwrap();
            outgoing.truncate(written);
            websocket.send(outgoing.into()).await.unwrap();
        }
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
}
