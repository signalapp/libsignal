//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;

use attest::client_connection::ClientConnection;
use attest::sgx_session::Handshake;
use futures_util::{Sink, SinkExt as _, Stream, StreamExt as _};
use http::uri::PathAndQuery;
use tokio_tungstenite::WebSocketStream;
use tungstenite::handshake::client::generate_key;
use tungstenite::protocol::{CloseFrame, WebSocketConfig};
use tungstenite::{http, Message};

use crate::infra::errors::NetError;
use crate::infra::{ConnectionParams, TransportConnector};

const WS_ALPN: &[u8] = b"\x08http/1.1";

pub(crate) async fn connect_websocket<T: TransportConnector>(
    connection_params: &ConnectionParams,
    endpoint: PathAndQuery,
    ws_config: WebSocketConfig,
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
    .await
    .map_err(|_| NetError::WsFailedHandshake)?;

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
pub(crate) struct WebSocket<S = WebSocketStream<tokio_boring::SslStream<tokio::net::TcpStream>>>(S);

impl<S> WebSocket<S> {
    pub(crate) fn new(stream: S) -> Self {
        Self(stream)
    }

    /// Sends a request on the connection.
    ///
    /// An error is returned if the send fails.
    pub(crate) async fn send(&mut self, item: TextOrBinary) -> Result<(), NetError>
    where
        S: Sink<Message, Error = tungstenite::Error>
            + Stream<Item = tungstenite::Result<Message>>
            + Unpin,
    {
        self.0
            .send(item.into())
            .await
            .map_err(|_: tungstenite::Error| NetError::Failure)
    }

    /// Receives a message on the connection.
    ///
    /// Returns the next text or binary message received on the wrapped socket.
    /// If the next response received is a [`Message::Close`], returns `None`.
    pub(crate) async fn receive(&mut self) -> Result<NextOrClose<TextOrBinary>, NetError>
    where
        S: Sink<Message, Error = tungstenite::Error>
            + Stream<Item = tungstenite::Result<Message>>
            + Unpin,
    {
        while let Some(message) = self.0.next().await {
            let output = match message {
                Ok(Message::Text(t)) => NextOrClose::Next(t.into()),
                Ok(Message::Binary(b)) => NextOrClose::Next(b.into()),
                Ok(Message::Close(frame)) => NextOrClose::Close(frame),
                Ok(Message::Ping(_) | Message::Pong(_)) => continue,
                Ok(Message::Frame(_)) => unreachable!("only for sending"),
                Err(tungstenite::Error::ConnectionClosed) => NextOrClose::Close(None),
                Err(_) => return Err(NetError::Failure),
            };
            return Ok(output);
        }
        Ok(NextOrClose::Close(None))
    }
}

#[derive(Debug)]
pub enum AttestedConnectionError {
    Protocol,
    ClientConnection(attest::client_connection::Error),
    Sgx(attest::sgx_session::Error),
    Net(NetError),
}

impl From<attest::sgx_session::Error> for AttestedConnectionError {
    fn from(value: attest::sgx_session::Error) -> Self {
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

/// Encrypted connection to an attested host.
#[derive(Debug)]
pub struct AttestedConnection<S = WebSocketStream<tokio_boring::SslStream<tokio::net::TcpStream>>> {
    websocket: WebSocket<S>,
    client_connection: ClientConnection,
}

#[derive(Clone, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
pub(crate) enum NextOrClose<T> {
    Next(T),
    Close(Option<CloseFrame<'static>>),
}

impl<T> NextOrClose<T> {
    pub(crate) fn next_or<E>(self, failure: E) -> Result<T, E> {
        match self {
            Self::Close(_) => Err(failure),
            Self::Next(t) => Ok(t),
        }
    }
}

impl<S> AttestedConnection<S>
where
    S: Sink<Message, Error = tungstenite::Error>
        + Stream<Item = tungstenite::Result<Message>>
        + Unpin,
{
    /// Connect to remote host and verify remote attestation.
    pub(crate) async fn connect(
        mut websocket: WebSocket<S>,
        new_handshake: impl FnOnce(&[u8]) -> Result<Handshake, attest::sgx_session::Error>,
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
        let request = self.client_connection.send(&request)?;
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

async fn authenticate<
    S: Stream<Item = tungstenite::Result<Message>> + Sink<Message, Error = tungstenite::Error> + Unpin,
>(
    websocket: &mut WebSocket<S>,
    new_handshake: impl FnOnce(&[u8]) -> Result<Handshake, attest::sgx_session::Error>,
) -> Result<attest::client_connection::ClientConnection, AttestedConnectionError> {
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
    use std::pin::Pin;

    use assert_matches::assert_matches;
    use futures_util::{pin_mut, poll};
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;
    use tokio_util::sync::PollSender;

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

    #[derive(Debug)]
    struct FakeWebsocket {
        sender: PollSender<Message>,
        receiver: ReceiverStream<Message>,
        receive_error: Option<tungstenite::Error>,
    }

    impl FakeWebsocket {
        const CHANNEL_SIZE: usize = 5;

        fn new_pair() -> (Self, Self) {
            let (sender_a, receiver_a) = mpsc::channel(Self::CHANNEL_SIZE);
            let (sender_b, receiver_b) = mpsc::channel(Self::CHANNEL_SIZE);
            (
                Self {
                    sender: PollSender::new(sender_a),
                    receiver: ReceiverStream::new(receiver_b),
                    receive_error: None,
                },
                Self {
                    sender: PollSender::new(sender_b),
                    receiver: ReceiverStream::new(receiver_a),
                    receive_error: None,
                },
            )
        }
    }

    impl Stream for FakeWebsocket {
        type Item = Result<Message, tungstenite::Error>;
        fn poll_next(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Self::Item>> {
            let Self {
                receiver,
                receive_error,
                ..
            } = self.get_mut();
            if let Some(error) = receive_error.take() {
                return std::task::Poll::Ready(Some(Err(error)));
            }
            Pin::new(receiver).poll_next(cx).map(|m| m.map(Ok))
        }
    }

    impl Sink<Message> for FakeWebsocket {
        type Error = tungstenite::Error;

        fn poll_ready(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            self.get_mut()
                .sender
                .poll_ready_unpin(cx)
                .map_err(|_| tungstenite::Error::AlreadyClosed)
        }

        fn start_send(self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
            self.get_mut()
                .sender
                .start_send_unpin(item)
                .map_err(|_| tungstenite::Error::AlreadyClosed)
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            self.get_mut()
                .sender
                .poll_flush_unpin(cx)
                .map_err(|_| tungstenite::Error::AlreadyClosed)
        }

        fn poll_close(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Result<(), Self::Error>> {
            self.get_mut()
                .sender
                .poll_close_unpin(cx)
                .map_err(|_| tungstenite::Error::AlreadyClosed)
        }
    }

    const MESSAGE_TEXT: &str = "text";

    #[tokio::test]
    async fn websocket_send_receive() {
        let (mut server, client) = FakeWebsocket::new_pair();

        let _echo = tokio::spawn(async move {
            while let Some(Ok(m)) = server.next().await {
                server.send(m).await.unwrap();
            }
        });

        let mut synchronous = WebSocket::new(client);
        let item = TextOrBinary::Text(MESSAGE_TEXT.into());

        synchronous.send(item.clone()).await.unwrap();
        let response = synchronous.receive().await.unwrap();
        assert_eq!(response, NextOrClose::Next(item));
    }

    #[tokio::test]
    async fn websocket_receive() {
        let (mut server, client) = FakeWebsocket::new_pair();

        let mut synchronous = WebSocket::new(client);
        let receive_unsolicited = synchronous.receive();
        pin_mut!(receive_unsolicited);

        assert_eq!(poll!(&mut receive_unsolicited), std::task::Poll::Pending);

        let item = TextOrBinary::Text(MESSAGE_TEXT.into());
        server.send(item.clone().into()).await.unwrap();

        assert_eq!(receive_unsolicited.await, Ok(NextOrClose::Next(item)));
    }

    #[tokio::test]
    async fn websocket_remote_hangs_up() {
        let (mut server, client) = FakeWebsocket::new_pair();

        let send_and_receive = async move {
            let mut ws = WebSocket::new(client);
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

    const FAKE_ATTESTATION: &[u8] = &[1; 32];

    /// Runs a fake SGX server that sets up a session and then echos back
    /// incoming messages.
    async fn run_attested_echo_server(
        websocket: impl Sink<tungstenite::Message, Error = tungstenite::Error>
            + Stream<Item = tungstenite::Result<tungstenite::Message>>
            + Unpin,
        private_key: impl AsRef<[u8]>,
    ) {
        let mut websocket = WebSocket::new(websocket);
        // Start the server with a known private key (K of NK).
        let mut server_hs =
            snow::Builder::new(attest::client_connection::NOISE_PATTERN.parse().unwrap())
                .local_private_key(private_key.as_ref())
                .build_responder()
                .unwrap();

        // The server first sends over it's attestation message.
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
        let (server, client) = FakeWebsocket::new_pair();
        tokio::task::spawn(run_attested_echo_server(
            server,
            attest::sgx_session::testutil::private_key(),
        ));

        let mut connection =
            AttestedConnection::connect(WebSocket::new(client), |fake_attestation| {
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
        let (server, client) = FakeWebsocket::new_pair();
        tokio::task::spawn(run_attested_echo_server(
            server,
            attest::sgx_session::testutil::private_key(),
        ));

        fn fail_to_handshake(
            _attestation: &[u8],
        ) -> attest::sgx_session::Result<attest::sgx_session::Handshake> {
            Err(attest::sgx_session::Error::AttestationDataError {
                reason: "invalid".to_string(),
            })
        }

        assert_matches!(
            AttestedConnection::connect(WebSocket::new(client), fail_to_handshake).await,
            Err(_)
        );
    }

    #[tokio::test]
    async fn attested_connection_invalid_decode() {
        // Start the server with a known private key (K of NK).
        let (server, client) = FakeWebsocket::new_pair();
        tokio::task::spawn(run_attested_echo_server(
            server,
            attest::sgx_session::testutil::private_key(),
        ));

        let mut connection =
            AttestedConnection::connect(WebSocket::new(client), |fake_attestation| {
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
