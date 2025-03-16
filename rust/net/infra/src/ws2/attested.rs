//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::sync::Arc;

use attest::client_connection::ClientConnection;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::CloseFrame;

use crate::ws::error::{ProtocolError, SpaceError, UnexpectedCloseError};
use crate::ws::{NextOrClose, TextOrBinary, WebSocketServiceError, WebSocketStreamLike};
use crate::ws2::{
    FinishReason, MessageEvent, NextEventError, Outcome, TungsteniteReceiveError,
    TungsteniteSendError,
};

/// Encrypted connection to an attested host.
#[derive(Debug)]
pub struct AttestedConnection {
    ws_client: WsClient,
    client_connection: ClientConnection,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum AttestedProtocolError {
    /// failed to decode frame as protobuf
    ProtobufDecode,
    /// received a text websocket frame
    TextFrame,
    /// {0}
    UnexpectedClose(UnexpectedCloseError),
}

#[derive(Debug, derive_more::From)]
pub enum AttestedConnectionError {
    Protocol(AttestedProtocolError),
    Attestation(attest::enclave::Error),
    WebSocket(WebSocketServiceError),
}

impl From<attest::client_connection::Error> for AttestedConnectionError {
    fn from(value: attest::client_connection::Error) -> Self {
        Self::Attestation(value.into())
    }
}

pub async fn run_attested_interaction<C: AsMut<AttestedConnection>, B: AsRef<[u8]>>(
    connection: &mut C,
    bytes: B,
) -> Result<NextOrClose<Vec<u8>>, AttestedConnectionError> {
    let connection = connection.as_mut();
    connection.send_bytes(bytes.as_ref()).await?;
    connection.receive_bytes().await
}

/// The number of messages the client can buffer outside of the websocket.
const WS_MESSAGE_BUFFER: usize = 2;

impl AttestedConnection {
    /// Establish an attested connection over the given stream.
    ///
    /// Perform a handshake over the provided websocket stream with the given
    /// handshake function. If the handshake succeeds, return the established
    /// connection.
    pub async fn connect<WS>(
        ws: WS,
        ws_config: crate::ws2::Config,
        log_tag: Arc<str>,
        new_handshake: impl FnOnce(&[u8]) -> attest::enclave::Result<attest::enclave::Handshake>,
    ) -> Result<Self, AttestedConnectionError>
    where
        WS: WebSocketStreamLike + Send + 'static,
    {
        let mut ws_client = WsClient::new(ws, ws_config, log_tag);

        let client_connection = authenticate(&mut ws_client, new_handshake).await?;

        Ok(Self {
            client_connection,
            ws_client,
        })
    }

    /// Read the next message from the stream, blocking until there is one.
    ///
    /// Waits for the next event from the server, then returns
    /// [`NextOrClose::Next`] with the message contents if there is one. If the
    /// server closed the stream, returns `NextOrClose::Close` with the contents
    /// of the close frame (if there is one). Returns an error if an unexpected
    /// condition is encountered.
    pub async fn receive_bytes(&mut self) -> Result<NextOrClose<Vec<u8>>, AttestedConnectionError> {
        let Self {
            ws_client,
            client_connection,
        } = self;

        let message = ws_client.read().await?;

        Ok(match message {
            NextOrClose::Next(message) => NextOrClose::Next(client_connection.recv(&message)?),
            NextOrClose::Close(close) => NextOrClose::Close(close),
        })
    }

    /// Write a message to the stream, blocking until it is sent.
    ///
    /// Returns an error if an unexpected condition is encountered.
    pub async fn send_bytes(&mut self, plaintext: &[u8]) -> Result<(), AttestedConnectionError> {
        let Self {
            ws_client,
            client_connection,
        } = self;

        let message = client_connection.send(plaintext)?;

        Ok(ws_client.write(message).await?)
    }

    /// Convenience function that binary-encodes a [`prost::Message`] and passes
    /// the bytes to [`AttestedConnection::send_bytes`].
    pub async fn send(
        &mut self,
        message: impl prost::Message,
    ) -> Result<(), AttestedConnectionError> {
        self.send_bytes(&message.encode_to_vec()).await
    }

    /// Convenience function that calls [`AttestedConnection::receive_bytes`]
    /// and decoes a received message as protobuf.
    pub async fn receive<M: prost::Message + Default>(
        &mut self,
    ) -> Result<NextOrClose<M>, AttestedConnectionError> {
        let next = self.receive_bytes().await?;
        match next {
            NextOrClose::Next(bytes) => M::decode(&*bytes).map(NextOrClose::Next).map_err(|_| {
                AttestedConnectionError::Protocol(AttestedProtocolError::ProtobufDecode)
            }),
            NextOrClose::Close(close_frame) => Ok(NextOrClose::Close(close_frame)),
        }
    }

    /// Get the hash of the Noise handshake.
    pub fn handshake_hash(&self) -> &[u8] {
        &self.client_connection.handshake_hash
    }
}

impl AsMut<Self> for AttestedConnection {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}

#[derive(Debug)]
struct WsClient {
    outgoing_tx: mpsc::Sender<(TextOrBinary, oneshot::Sender<Result<(), SendError>>)>,
    incoming_rx: mpsc::Receiver<Result<NextOrClose<TextOrBinary>, ReceiveError>>,
}

impl WsClient {
    fn new<WS>(ws: WS, ws_config: crate::ws2::Config, log_tag: Arc<str>) -> Self
    where
        WS: WebSocketStreamLike + Send + 'static,
    {
        let (outgoing_tx, outgoing_rx) = mpsc::channel(WS_MESSAGE_BUFFER);
        let (incoming_tx, incoming_rx) = mpsc::channel(WS_MESSAGE_BUFFER);

        let _task = tokio::spawn(spawned_task_body(
            ws,
            outgoing_rx,
            incoming_tx,
            ws_config,
            log_tag,
        ));

        Self {
            outgoing_tx,
            incoming_rx,
        }
    }

    async fn write(&mut self, message: impl Into<TextOrBinary>) -> Result<(), SendError> {
        let (sender, receiver) = oneshot::channel();
        self.outgoing_tx
            .send((message.into(), sender))
            .await
            .map_err(SendError::from)?;

        receiver.await??;
        Ok(())
    }

    async fn read(&mut self) -> Result<NextOrClose<Vec<u8>>, ReceiveError> {
        let recv = self
            .incoming_rx
            .recv()
            .await
            .ok_or(ReceiveError::UnexpectedConnectionClose)??;
        match recv {
            NextOrClose::Next(TextOrBinary::Text(_)) => Err(ReceiveError::UnexpectedTextMessage),
            NextOrClose::Next(TextOrBinary::Binary(vec)) => Ok(NextOrClose::Next(vec)),
            NextOrClose::Close(close) => Ok(NextOrClose::Close(close)),
        }
    }
}

#[derive(Debug)]
pub enum SendError {
    ConnectionClosed,
    WebSocketProtocol(ProtocolError),
    Io(std::io::Error),
    MessageTooLarge { size: usize, max_size: usize },
}

#[derive(Debug)]
pub enum ReceiveError {
    WebSocketSend(TungsteniteSendError),
    WebSocketReceive(crate::ws2::TungsteniteReceiveError),
    ServerIdleTooLong(std::time::Duration),
    UnexpectedConnectionClose,
    UnexpectedTextMessage,
}

#[derive(Debug, displaydoc::Display)]
enum TaskExitError {
    /// received Close with code {code}
    AbnormalServerClose { code: CloseCode },
    /// send failed: {0}
    SendFailed(&'static str),
    /// server didn't respond for too long
    ServerIdleTooLong,
    /// the transport was closed unexpectedly
    UnexpectedConnectionClose,
    /// websocket error: {0}
    WebSocketProtocol(tungstenite::error::ProtocolError),
    /// IO error: {0}
    Io(std::io::ErrorKind),
    /// server sent invalid UTF-8
    ReceivedInvalidUtf8,
}

async fn spawned_task_body(
    stream: impl WebSocketStreamLike,
    outgoing_rx: mpsc::Receiver<(TextOrBinary, oneshot::Sender<Result<(), SendError>>)>,
    incoming_tx: mpsc::Sender<Result<NextOrClose<TextOrBinary>, ReceiveError>>,
    config: crate::ws2::Config,
    log_tag: Arc<str>,
) -> Result<(), TaskExitError> {
    let mut connection = crate::ws2::Connection::new(
        stream,
        ReceiverStream::new(outgoing_rx),
        config,
        log_tag.clone(),
    );
    let mut connection = std::pin::pin!(connection);

    loop {
        match connection.as_mut().handle_next_event().await {
            Outcome::Continue(event) => match event {
                MessageEvent::SentMessage(response_sender) => {
                    if response_sender.send(Ok(())).is_err() {
                        log::debug!(
                            "[{log_tag}] failed to signal send because the sender was dropped"
                        );
                    }
                }
                MessageEvent::SendFailed(response_sender, tungstenite_send_error) => {
                    let task_err = TaskExitError::from(&tungstenite_send_error);
                    if response_sender
                        .send(Err(tungstenite_send_error.into()))
                        .is_err()
                    {
                        log::debug!("[{log_tag}] failed to signal send error because the sender was dropped");
                    }
                    return Err(task_err);
                }
                MessageEvent::ReceivedMessage(text_or_binary) => {
                    if incoming_tx
                        .send(Ok(NextOrClose::Next(text_or_binary)))
                        .await
                        .is_err()
                    {
                        log::debug!(
                            "[{log_tag}] failed to forward received message because the receiver was dropped"
                        );
                        // The receiver has been dropped, so we should exit.
                        return Ok(());
                    }
                }
                MessageEvent::SentPing | MessageEvent::ReceivedPingPong => (),
            },
            Outcome::Finished(Ok(FinishReason::RemoteDisconnect)) => {
                if incoming_tx
                    .send(Ok(NextOrClose::Close(None)))
                    .await
                    .is_err()
                {
                    log::debug!(
                        "[{log_tag}] failed to send close event because the receiver was dropped"
                    )
                }
                return Ok(());
            }
            Outcome::Finished(Ok(FinishReason::LocalDisconnect)) => {
                return Ok(());
            }

            Outcome::Finished(Err(err)) => {
                let (exit_error, tx_error) = match err {
                    NextEventError::AbnormalServerClose { code, reason } => {
                        if incoming_tx
                            .send(Ok(NextOrClose::Close(Some(CloseFrame {
                                code,
                                reason: Cow::Owned(reason),
                            }))))
                            .await
                            .is_err()
                        {
                            log::debug!("[{log_tag}] failed to send abnormal close event because the receiver was dropped");
                        }
                        return Err(TaskExitError::AbnormalServerClose { code });
                    }
                    NextEventError::PingFailed(tungstenite_send_error)
                    | NextEventError::CloseFailed(tungstenite_send_error) => {
                        let exit_error = TaskExitError::from(&tungstenite_send_error);
                        (
                            exit_error,
                            ReceiveError::WebSocketSend(tungstenite_send_error),
                        )
                    }
                    NextEventError::ReceiveError(tungstenite_receive_error) => (
                        TaskExitError::from(&tungstenite_receive_error),
                        ReceiveError::WebSocketReceive(tungstenite_receive_error),
                    ),
                    NextEventError::ServerIdleTimeout(duration) => (
                        TaskExitError::ServerIdleTooLong,
                        ReceiveError::ServerIdleTooLong(duration),
                    ),
                    NextEventError::UnexpectedConnectionClose => (
                        TaskExitError::UnexpectedConnectionClose,
                        ReceiveError::UnexpectedConnectionClose,
                    ),
                };
                if incoming_tx.send(Err(tx_error)).await.is_err() {
                    log::debug!(
                        "[{log_tag}] failed to signal send error because the receiver was dropped"
                    )
                }
                return Err(exit_error);
            }
        }
    }
}

async fn authenticate(
    websocket: &mut WsClient,
    new_handshake: impl FnOnce(&[u8]) -> attest::enclave::Result<attest::enclave::Handshake>,
) -> Result<ClientConnection, AttestedConnectionError> {
    let attestation_msg = websocket.read().await?.next_or_else(|close| {
        AttestedConnectionError::Protocol(AttestedProtocolError::UnexpectedClose(close.into()))
    })?;
    let handshake = new_handshake(attestation_msg.as_ref())?;

    websocket
        .write(Vec::from(handshake.initial_request()))
        .await?;

    let initial_response = websocket.read().await?.next_or_else(|close| {
        AttestedConnectionError::Protocol(AttestedProtocolError::UnexpectedClose(close.into()))
    })?;

    Ok(handshake.complete(&initial_response)?)
}

impl From<oneshot::error::RecvError> for SendError {
    fn from(_: oneshot::error::RecvError) -> Self {
        // The task shut down before sending an outgoing message.
        SendError::ConnectionClosed
    }
}

impl<T> From<mpsc::error::SendError<T>> for SendError {
    fn from(_: mpsc::error::SendError<T>) -> Self {
        // The task isn't listening for messages any more.
        SendError::ConnectionClosed
    }
}

impl From<TungsteniteSendError> for SendError {
    fn from(value: TungsteniteSendError) -> Self {
        match value {
            TungsteniteSendError::ConnectionAlreadyClosed => SendError::ConnectionClosed,
            TungsteniteSendError::Io(error) => SendError::Io(error),
            TungsteniteSendError::MessageTooLarge { size, max_size } => {
                SendError::MessageTooLarge { size, max_size }
            }
            TungsteniteSendError::WebSocketProtocol(protocol_error) => {
                SendError::WebSocketProtocol(ProtocolError::from(protocol_error))
            }
        }
    }
}

impl From<&TungsteniteSendError> for TaskExitError {
    fn from(value: &TungsteniteSendError) -> Self {
        match value {
            TungsteniteSendError::ConnectionAlreadyClosed => {
                TaskExitError::SendFailed("on closed connection")
            }
            TungsteniteSendError::Io(error) => TaskExitError::Io(error.kind()),
            TungsteniteSendError::MessageTooLarge { .. } => {
                TaskExitError::SendFailed("message too large")
            }
            TungsteniteSendError::WebSocketProtocol(protocol_error) => {
                TaskExitError::WebSocketProtocol(protocol_error.clone())
            }
        }
    }
}

impl From<&TungsteniteReceiveError> for TaskExitError {
    fn from(value: &TungsteniteReceiveError) -> Self {
        match value {
            TungsteniteReceiveError::Io(error) => TaskExitError::Io(error.kind()),
            TungsteniteReceiveError::MessageTooLarge { .. } => {
                TaskExitError::SendFailed("message too large (receive)")
            }
            TungsteniteReceiveError::WebSocketProtocol(protocol_error) => {
                TaskExitError::WebSocketProtocol(protocol_error.clone())
            }
            TungsteniteReceiveError::ServerSentInvalidUtf8 => TaskExitError::ReceivedInvalidUtf8,
        }
    }
}

impl From<ReceiveError> for AttestedConnectionError {
    fn from(value: ReceiveError) -> Self {
        match value {
            ReceiveError::WebSocketSend(tungstenite_send_error) => {
                AttestedConnectionError::WebSocket(tungstenite_send_error.into())
            }
            ReceiveError::WebSocketReceive(tungstenite_receive_error) => {
                AttestedConnectionError::WebSocket(tungstenite_receive_error.into())
            }
            ReceiveError::ServerIdleTooLong(_duration) => {
                AttestedConnectionError::WebSocket(WebSocketServiceError::ChannelIdleTooLong)
            }
            ReceiveError::UnexpectedConnectionClose => AttestedConnectionError::Protocol(
                AttestedProtocolError::UnexpectedClose(UnexpectedCloseError::from(None)),
            ),
            ReceiveError::UnexpectedTextMessage => {
                AttestedConnectionError::Protocol(AttestedProtocolError::TextFrame)
            }
        }
    }
}

impl From<SendError> for AttestedConnectionError {
    fn from(value: SendError) -> Self {
        match value {
            SendError::ConnectionClosed => AttestedConnectionError::Protocol(
                AttestedProtocolError::UnexpectedClose(UnexpectedCloseError::from(None)),
            ),
            SendError::WebSocketProtocol(protocol_error) => {
                AttestedConnectionError::WebSocket(WebSocketServiceError::Protocol(protocol_error))
            }
            SendError::Io(error) => {
                AttestedConnectionError::WebSocket(WebSocketServiceError::Io(error))
            }
            SendError::MessageTooLarge { size, max_size } => AttestedConnectionError::WebSocket(
                WebSocketServiceError::Capacity(SpaceError::Capacity(
                    tungstenite::error::CapacityError::MessageTooLong { size, max_size },
                )),
            ),
        }
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod testutil {
    use std::fmt::Debug;

    use tokio_tungstenite::WebSocketStream;

    use super::*;
    use crate::ws::testutil::websocket_test_client;
    use crate::AsyncDuplexStream;

    pub const FAKE_ATTESTATION: &[u8] =
        include_bytes!("../../../../attest/tests/data/svr2handshakestart.data");

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

    impl TextOrBinary {
        pub fn try_into_binary(self) -> Result<Vec<u8>, AttestedConnectionError> {
            match self {
                TextOrBinary::Text(_) => Err(AttestedConnectionError::Protocol(
                    AttestedProtocolError::TextFrame,
                )),
                TextOrBinary::Binary(b) => Ok(b),
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

        // The type is poorly named but works here since it just wraps an
        // already-established connection.
        let mut server_connection = ClientConnection {
            handshake_hash: server_hs.get_handshake_hash().to_vec(),
            transport: server_hs.into_transport_mode().unwrap(),
        };

        while let Ok(incoming) = websocket.receive().await {
            let received = match incoming {
                NextOrClose::Close(close) => NextOrClose::Close(close),
                NextOrClose::Next(incoming) => {
                    let incoming = incoming.try_into_binary().unwrap();
                    let payload = server_connection.recv(&incoming).unwrap();

                    NextOrClose::Next(payload)
                }
            };

            let AttestedServerOutput {
                close_after,
                message,
            } = on_message(received);

            if let Some(payload) = message {
                let outgoing = server_connection.send(&payload).unwrap();
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
    use std::time::Duration;

    use assert_matches::assert_matches;
    use tokio_tungstenite::WebSocketStream;

    use super::*;
    use crate::ws::testutil::fake_websocket;
    use crate::ws2::attested::testutil::{
        run_attested_server, AttestedServerOutput, FAKE_ATTESTATION,
    };
    use crate::AsyncDuplexStream;

    const ECHO_BYTES: &[u8] = b"two nibbles to a byte";

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

    const FAKE_WS_CONFIG: crate::ws2::Config = crate::ws2::Config {
        local_idle_timeout: Duration::from_secs(10),
        remote_idle_ping_timeout: Duration::from_secs(10),
        remote_idle_disconnect_timeout: Duration::from_secs(20),
    };

    #[tokio::test]
    async fn attested_connection_happy_path() {
        // Start the server with a known private key (K of NK).
        let (server, client) = fake_websocket().await;
        tokio::task::spawn(run_attested_echo_server(
            server,
            attest::sgx_session::testutil::private_key(),
        ));

        let mut connection = AttestedConnection::connect(
            client,
            FAKE_WS_CONFIG,
            "test".into(),
            |fake_attestation| {
                assert_eq!(fake_attestation, FAKE_ATTESTATION);
                attest::sgx_session::testutil::handshake_from_tests_data()
            },
        )
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

        fn fail_to_handshake(
            _attestation: &[u8],
        ) -> attest::enclave::Result<attest::enclave::Handshake> {
            Err(attest::enclave::Error::AttestationDataError {
                reason: "invalid".to_string(),
            })
        }

        assert_matches!(
            AttestedConnection::connect(client, FAKE_WS_CONFIG, "test".into(), fail_to_handshake)
                .await,
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

        let mut connection = AttestedConnection::connect(
            client,
            FAKE_WS_CONFIG,
            "test".into(),
            |fake_attestation| {
                assert_eq!(fake_attestation, FAKE_ATTESTATION);
                attest::sgx_session::testutil::handshake_from_tests_data()
            },
        )
        .await
        .unwrap();

        connection.send(Vec::from(ECHO_BYTES)).await.unwrap();
        // Decoding a vec as a 32-bit float shouldn't work.
        assert_matches!(
            connection.receive::<f32>().await.expect_err("wrong type"),
            AttestedConnectionError::Protocol(AttestedProtocolError::ProtobufDecode)
        );
    }
}
