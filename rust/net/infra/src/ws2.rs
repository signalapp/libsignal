//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;
use std::io::Error as IoError;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::{SinkExt as _, Stream, StreamExt as _};
use pin_project::pin_project;
use tokio::select;
use tokio::time::{Duration, Instant};
use tungstenite::protocol::frame::coding::CloseCode;
use tungstenite::protocol::CloseFrame;
use tungstenite::Message;

use crate::errors::LogSafeDisplay;
use crate::ws::{TextOrBinary, WebSocketServiceError, WebSocketStreamLike};

pub mod attested;

/// Configuration values for managing the connected websocket.
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

/// An established websocket connection.
///
/// This wraps the client end of a websocket (typically a
/// [`tokio_tungstenite::WebSocketStream`]) and the receiving end of an outgoing
/// [`Stream`] of messages `R` and handles communicating outgoing messages to,
/// and handling incoming messages and events from, the server on the other end
/// of the websocket.
///
/// A `Connection` instance represents an established, but not necessarily
/// still-open, connection. It emits events to the owner via calls to
/// [`Connection::handle_next_event`].
///
/// This requires being wrapped with `Pin` since the internal
/// [`tokio::time::Sleep`] field needs to be pinned; helpfully this lets us also
/// not require that `S` and `R` are `Unpin`.
#[pin_project(project = ConnectionProj)]
pub struct Connection<S, R> {
    /// The client end of a websocket.
    ///
    /// This should implement [`Stream`] and [`Sink`] for websocket [`Message`]s.
    #[pin]
    stream: S,

    /// A stream of incoming messages to send out the websocket.
    #[pin]
    outgoing_rx: R,

    /// A saved future that is used for timeouts while waiting for events.
    ///
    /// This could be constructed anew in each call to
    /// [`Connection::handle_next_event`], but doing so would be inefficient.
    /// Cache it for reuse instead, though that requires `Connection` be
    /// [`Pin`]ned to be used.
    #[pin]
    inactivity_sleep: tokio::time::Sleep,

    /// The single-byte content of the next ping frame.
    ping_count: u8,

    /// The last time that any outgoing message was sent to the server.
    last_sent_to_server: Option<Instant>,

    /// The last time that a [`Message::Ping`] was sent to the server.
    ///
    /// This is always <= `last_sent_to_server`.
    last_sent_ping_to_server: Option<Instant>,

    /// The last time that a message was received from the server.
    last_heard_from_server: Option<Instant>,

    /// Configuration for this websocket client's behavior.
    config: Config,

    /// A tag to include in log lines, to disambiguate multiple websockets.
    log_tag: Arc<str>,
}

/// Fatal error that causes a connection to be closed.
#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum NextEventError {
    /// tried to send a ping frame but the send failed
    PingFailed(TungsteniteSendError),
    /// tried to send a close frame but the send failed
    CloseFailed(TungsteniteSendError),
    /// the server closed the connection abnormally with code {code}.
    AbnormalServerClose { code: CloseCode, reason: String },
    /// failed to receive incoming messages.
    ReceiveError(#[from] TungsteniteReceiveError),
    /// no frames received from server for {0:?}
    ServerIdleTimeout(Duration),
    /// the server closed the connection unexpectedly
    UnexpectedConnectionClose,
}

/// Event that can occur while (asynchronously) waiting.
#[derive(Debug)]
pub enum MessageEvent<Meta> {
    /// A message was successfully sent.
    ///
    /// Contains metadata about the message that was produced when getting ready
    /// to send the message.
    SentMessage(Meta),
    /// An outgoing frame wasn't sent successfully.
    SendFailed(Meta, TungsteniteSendError),
    /// A message was received from the server.
    ReceivedMessage(TextOrBinary),
    /// A ping was sent successfully.
    SentPing,
    /// A ping or pong frame were received.
    ReceivedPingPong,
}

/// Why the task finished.
///
/// This can't necessarily be precise since there are network delays and
/// queueing involved and so a "simultaneous" disconnect can result in each side
/// seeing a different outcome.
#[derive(Copy, Clone, Debug, PartialEq, Eq, strum::Display)]
#[strum(serialize_all = "lowercase")]
pub enum FinishReason {
    /// The local end disconnected first.
    LocalDisconnect,
    /// The remote end disconnected first.
    RemoteDisconnect,
}

/// Errors that can occur when sending.
///
/// This is a subset of the cases in [`tungstenite::Error`] that can be returned
/// in response to sending on an established (post-handshake) connection. It was
/// manually produced by tracing through original sites for all the possible
/// errors and seeing where those intersected calls originating from
/// [`tokio_tungstenite::WebSocketStream`]'s `send()` and friends.
#[derive(Debug, thiserror::Error)]
pub enum TungsteniteSendError {
    /// Like [`tungstenite::Error::AlreadyClosed`].
    ConnectionAlreadyClosed,
    /// Like [`tungstenite::Error::Io`].
    Io(IoError),
    /// The outgoing messages was larger than the maximum bufferable size.
    MessageTooLarge { size: usize, max_size: usize },
    /// Websocket-level protocol error
    WebSocketProtocol(tungstenite::error::ProtocolError),
}

/// Errors that can occur when trying to read from a websocket.
///
/// This is a subset of the cases in [`tungstenite::Error`] that can be returned
/// in response to receiving on an established (post-handshake) connection. It
/// was manually produced by tracing through original sites for all the possible
/// errors and seeing where those intersected calls originating from
/// [`tokio_tungstenite::WebSocketStream`]'s `next()` and friends.
#[derive(Debug, thiserror::Error)]
pub enum TungsteniteReceiveError {
    /// Like [`tungstenite::Error::Io`].
    Io(IoError),
    /// The server sent a message that was larger than the maximum bufferable
    /// size
    MessageTooLarge { size: usize, max_size: usize },
    /// Websocket-level protocol error
    WebSocketProtocol(tungstenite::error::ProtocolError),
    /// The server sent a text frame containing invalid UTF-8.
    ServerSentInvalidUtf8,
}

/// The outcome of calling [`Connection::handle_next_event`].
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum Outcome<C, F> {
    Continue(C),
    Finished(F),
}

impl<S, R, SendMeta> Connection<S, R>
where
    R: Stream<Item = (TextOrBinary, SendMeta)>,
{
    pub fn new(stream: S, outgoing_rx: R, config: Config, log_tag: Arc<str>) -> Self {
        Self {
            stream,
            outgoing_rx,
            config,
            inactivity_sleep: tokio::time::sleep(Duration::ZERO),
            ping_count: 0,
            last_heard_from_server: None,
            last_sent_to_server: None,
            last_sent_ping_to_server: None,
            log_tag,
        }
    }

    /// Wait for the first available event, returning the outcome.
    ///
    /// The events that can be handled include
    /// - the client puts a message in the outgoing queue (`self.outgoing_rx`)
    /// - a message comes in from the server
    /// - the server closes the connection
    /// - the client hangs up on the outgoing queue
    /// - the websocket is quiet for too long and a Ping is sent
    ///
    /// Events that should terminate the connection are returned as a
    /// [`Outcome::Finished`] value; others are returned as
    /// [`Outcome::Continue`]. Once this function returns
    /// `Outcome::Finished` it should not be called again.
    ///
    /// This function takes as input a single argument that transforms an
    /// outgoing message into a websocket-compatible [`TextOrBinary`] instance
    /// and some metadata that will be returned to the caller if an outgoing
    /// message is actually sent. Simple use cases can simply use `|m| (m, ())`
    /// to pass through an input `TextOrBinary` unmodified.
    pub async fn handle_next_event(
        self: Pin<&mut Self>,
    ) -> Outcome<MessageEvent<SendMeta>, Result<FinishReason, NextEventError>>
    where
        S: WebSocketStreamLike,
    {
        let ConnectionProj {
            mut stream,
            mut outgoing_rx,
            mut inactivity_sleep,
            ping_count,
            config:
                Config {
                    local_idle_timeout,
                    remote_idle_ping_timeout,
                    remote_idle_disconnect_timeout,
                },
            last_sent_to_server,
            last_sent_ping_to_server,
            last_heard_from_server,
            log_tag,
        } = self.project();

        // For the first call this function, assume we just heard from & sent to
        // the server. Later calls will use the recorded values from previous
        // calls.
        let now = Instant::now();
        let last_heard_from_server = last_heard_from_server.get_or_insert(now);
        let last_sent_to_server = last_sent_to_server.get_or_insert(now);
        let last_sent_ping_to_server = last_sent_ping_to_server.get_or_insert(now);

        #[derive(Debug)]
        enum Event<M> {
            ClientDisconnect,
            ToSend(M),
            ServerDisconnect,
            Received(Result<Message, tungstenite::Error>),
            ConnectionIdle,
            RemoteDisconnectedTimeout,
        }

        let (earliest_timeout, inactivity_event) = {
            // If we haven't sent anything to the server in a while, send a ping to
            // make sure that it knows we're still around.
            let local_connection_idle_timeout = (
                *last_sent_to_server + *local_idle_timeout,
                Event::ConnectionIdle,
            );

            // If we haven't heard anything from the server in a while, send it a
            // ping to make sure it's still around. Don't be too eager, though: if
            // we sent a ping recently, don't keep spamming the server.
            let remote_connection_idle = (
                Instant::max(*last_sent_ping_to_server, *last_heard_from_server)
                    + *remote_idle_ping_timeout,
                Event::ConnectionIdle,
            );

            // If we haven't heard from the server for long enough, declare the
            // connection dead.
            let remote_connection_disconnected = (
                *last_heard_from_server + *remote_idle_disconnect_timeout,
                Event::RemoteDisconnectedTimeout,
            );

            [
                local_connection_idle_timeout,
                remote_connection_idle,
                remote_connection_disconnected,
            ]
            .into_iter()
            .min_by_key(|(time, _)| *time)
            .expect("non-empty array")
        };

        inactivity_sleep.as_mut().reset(earliest_timeout);

        let event = select! {
            to_send = outgoing_rx.next() => to_send.map_or(Event::ClientDisconnect, Event::ToSend),
            recv = stream.next() => recv.map_or(Event::ServerDisconnect, Event::Received),
            () = inactivity_sleep.as_mut() => inactivity_event,
        };

        match event {
            Event::RemoteDisconnectedTimeout => {
                // The server is expected to send frames every so often (either
                // messages or responses to our pings). We haven't gotten one in
                // a while, so assume the connection was broken.
                Outcome::Finished(Err(NextEventError::ServerIdleTimeout(
                    *remote_idle_disconnect_timeout,
                )))
            }
            Event::ConnectionIdle => {
                *ping_count = ping_count.wrapping_add(1);
                match stream
                    .send(Message::Ping(vec![*ping_count]))
                    .await
                    .map_err(|e| TungsteniteSendError::from(TungsteniteError::from(e)))
                {
                    Ok(()) => {
                        let now = Instant::now();
                        *last_sent_to_server = now;
                        *last_sent_ping_to_server = now;
                        Outcome::Continue(MessageEvent::SentPing)
                    }
                    Err(err) => Outcome::Finished(Err(NextEventError::PingFailed(err))),
                }
            }
            Event::ClientDisconnect => {
                // The client has been closed, so there aren't any more messages
                // coming in. Tell the server we're done.
                let result = stream.send(Message::Close(None)).await;
                Outcome::Finished(match result {
                    Ok(()) => Ok(FinishReason::LocalDisconnect),
                    Err(e) => Err({
                        let e = TungsteniteSendError::from(TungsteniteError::from(e));
                        NextEventError::CloseFailed(e)
                    }),
                })
            }
            Event::ToSend((message, meta)) => {
                let event = match stream.send(message.into()).await {
                    Ok(()) => {
                        *last_sent_to_server = Instant::now();
                        MessageEvent::SentMessage(meta)
                    }
                    Err(e) => {
                        let e = TungsteniteSendError::from(TungsteniteError::from(e));
                        MessageEvent::SendFailed(meta, e)
                    }
                };
                Outcome::Continue(event)
            }
            Event::ServerDisconnect => {
                // The server closed our connection without sending a
                // `Message::Close` frame.
                Outcome::Finished(Err(NextEventError::UnexpectedConnectionClose))
            }
            Event::Received(Ok(message)) => {
                *last_heard_from_server = Instant::now();
                match message {
                    Message::Text(text) => {
                        Outcome::Continue(MessageEvent::ReceivedMessage(TextOrBinary::Text(text)))
                    }
                    Message::Binary(binary) => Outcome::Continue(MessageEvent::ReceivedMessage(
                        TextOrBinary::Binary(binary),
                    )),
                    Message::Ping(_) | Message::Pong(_) => {
                        // tungstenite handles pings internally, nothing to do here.
                        Outcome::Continue(MessageEvent::ReceivedPingPong)
                    }
                    Message::Close(close) => {
                        let code = close.as_ref().map(|c| c.code);
                        log::info!(
                            "[{log_tag}] received a close frame from the server with code {code:?}",
                        );
                        match close {
                            None
                            | Some(CloseFrame {
                                code: CloseCode::Normal,
                                ..
                            }) => Outcome::Finished(Ok(FinishReason::RemoteDisconnect)),
                            Some(CloseFrame { code, reason }) => {
                                Outcome::Finished(Err(NextEventError::AbnormalServerClose {
                                    code,
                                    reason: reason.into_owned(),
                                }))
                            }
                        }
                    }
                    Message::Frame(_) => {
                        unreachable!("Message::Frame is never returned for a read")
                    }
                }
            }
            Event::Received(Err(err)) => Outcome::Finished(Err(NextEventError::ReceiveError(
                match TungsteniteError::from(err) {
                    TungsteniteError::ConnectionClosed | TungsteniteError::AlreadyClosed => {
                        unreachable!(concat!(
                            "tungstenite-tokio signals connection closed ",
                            "as end of stream, not error"
                        ))
                    }

                    TungsteniteError::Io(io) => TungsteniteReceiveError::Io(io),
                    TungsteniteError::CapacityErrorMessageTooLarge { size, max_size } => {
                        TungsteniteReceiveError::MessageTooLarge { size, max_size }
                    }
                    TungsteniteError::Protocol(err) => {
                        TungsteniteReceiveError::WebSocketProtocol(err)
                    }
                    TungsteniteError::WriteBufferFull => {
                        unreachable!("this client flushes after every write")
                    }
                    TungsteniteError::Utf8 => TungsteniteReceiveError::ServerSentInvalidUtf8,
                },
            ))),
        }
    }
}

impl LogSafeDisplay for TungsteniteSendError {}
impl Display for TungsteniteSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TungsteniteSendError::ConnectionAlreadyClosed => {
                write!(f, "the connection is already closed")
            }
            TungsteniteSendError::Io(io) => write!(f, "IO error: {}", io.kind()),
            TungsteniteSendError::MessageTooLarge { size, max_size } => write!(
                f,
                "max message size is {max_size} bytes, tried to send {size}"
            ),
            TungsteniteSendError::WebSocketProtocol(err) => {
                write!(f, "websocket protocol error: {err}")
            }
        }
    }
}

impl Display for TungsteniteReceiveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TungsteniteReceiveError::Io(io) => write!(f, "IO error: {}", io.kind()),
            TungsteniteReceiveError::MessageTooLarge { size, max_size } => write!(
                f,
                "max message size is {max_size} bytes, tried to send {size}"
            ),
            TungsteniteReceiveError::WebSocketProtocol(err) => {
                write!(f, "websocket protocol error: {err}")
            }
            TungsteniteReceiveError::ServerSentInvalidUtf8 => {
                write!(f, "server sent invalid UTF-8")
            }
        }
    }
}

impl From<TungsteniteError> for TungsteniteSendError {
    fn from(value: TungsteniteError) -> Self {
        match value {
            TungsteniteError::ConnectionClosed | TungsteniteError::AlreadyClosed => {
                TungsteniteSendError::ConnectionAlreadyClosed
            }
            TungsteniteError::Io(io) => TungsteniteSendError::Io(io),
            TungsteniteError::CapacityErrorMessageTooLarge { size, max_size } => {
                TungsteniteSendError::MessageTooLarge { size, max_size }
            }
            TungsteniteError::Protocol(e) => TungsteniteSendError::WebSocketProtocol(e),
            TungsteniteError::WriteBufferFull => {
                unreachable!("can only be produced in start_send")
            }
            TungsteniteError::Utf8 => unreachable!("no UTF-8 validation happens on send"),
        }
    }
}
impl From<TungsteniteSendError> for TungsteniteError {
    fn from(value: TungsteniteSendError) -> Self {
        match value {
            TungsteniteSendError::ConnectionAlreadyClosed => Self::ConnectionClosed,
            TungsteniteSendError::Io(error) => Self::Io(error),
            TungsteniteSendError::MessageTooLarge { size, max_size } => {
                Self::CapacityErrorMessageTooLarge { size, max_size }
            }
            TungsteniteSendError::WebSocketProtocol(protocol_error) => {
                Self::Protocol(protocol_error)
            }
        }
    }
}

impl From<TungsteniteError> for TungsteniteReceiveError {
    fn from(value: TungsteniteError) -> Self {
        match value {
            TungsteniteError::ConnectionClosed | TungsteniteError::AlreadyClosed => {
                unreachable!(
                    "tungstenite-tokio signals connection closed as end of stream, not error"
                )
            }
            TungsteniteError::Io(io) => TungsteniteReceiveError::Io(io),
            TungsteniteError::CapacityErrorMessageTooLarge { size, max_size } => {
                TungsteniteReceiveError::MessageTooLarge { size, max_size }
            }
            TungsteniteError::Protocol(e) => TungsteniteReceiveError::WebSocketProtocol(e),

            TungsteniteError::WriteBufferFull => {
                unreachable!("can only be produced in start_send")
            }
            TungsteniteError::Utf8 => unreachable!("no UTF-8 validation happens on send"),
        }
    }
}
impl From<TungsteniteReceiveError> for TungsteniteError {
    fn from(value: TungsteniteReceiveError) -> Self {
        match value {
            TungsteniteReceiveError::Io(error) => Self::Io(error),
            TungsteniteReceiveError::MessageTooLarge { size, max_size } => {
                Self::CapacityErrorMessageTooLarge { size, max_size }
            }
            TungsteniteReceiveError::WebSocketProtocol(protocol_error) => {
                Self::Protocol(protocol_error)
            }
            TungsteniteReceiveError::ServerSentInvalidUtf8 => Self::Utf8,
        }
    }
}

impl From<TungsteniteSendError> for WebSocketServiceError {
    fn from(value: TungsteniteSendError) -> Self {
        TungsteniteError::from(value).into()
    }
}

impl From<TungsteniteReceiveError> for WebSocketServiceError {
    fn from(value: TungsteniteReceiveError) -> Self {
        TungsteniteError::from(value).into()
    }
}

impl From<TungsteniteError> for WebSocketServiceError {
    fn from(value: TungsteniteError) -> Self {
        match value {
            TungsteniteError::AlreadyClosed | TungsteniteError::ConnectionClosed => {
                Self::ChannelClosed
            }
            TungsteniteError::Io(error) => Self::Io(error),
            TungsteniteError::CapacityErrorMessageTooLarge { size, max_size } => {
                Self::Capacity(crate::ws::error::SpaceError::Capacity(
                    tungstenite::error::CapacityError::MessageTooLong { size, max_size },
                ))
            }
            TungsteniteError::Protocol(protocol_error) => Self::Protocol(protocol_error.into()),
            TungsteniteError::WriteBufferFull => {
                Self::Capacity(crate::ws::error::SpaceError::SendQueueFull)
            }
            TungsteniteError::Utf8 => Self::Other("UTF-8 error"),
        }
    }
}

impl From<tungstenite::Error> for TungsteniteError {
    fn from(value: tungstenite::Error) -> Self {
        match value {
            tungstenite::Error::ConnectionClosed => Self::ConnectionClosed,
            tungstenite::Error::AlreadyClosed => Self::AlreadyClosed,
            tungstenite::Error::Io(io) => Self::Io(io),
            tungstenite::Error::Capacity(tungstenite::error::CapacityError::MessageTooLong {
                size,
                max_size,
            }) => Self::CapacityErrorMessageTooLarge { size, max_size },
            tungstenite::Error::Protocol(e) => Self::Protocol(e),
            tungstenite::Error::Utf8 => Self::Utf8,

            tungstenite::Error::WriteBufferFull(_) => Self::WriteBufferFull,
            tungstenite::Error::Url(_) => {
                unreachable!("URL processing does not occur after handshake")
            }
            tungstenite::Error::HttpFormat(_) | tungstenite::Error::Http(_) => {
                unreachable!("HTTP processing does not occur after handshake")
            }
            tungstenite::Error::AttackAttempt => {
                unreachable!("only occurs during websocket handshake")
            }
            tungstenite::Error::Tls(_) => {
                unreachable!("TLS handling is below the scope of tunstenite")
            }
            tungstenite::Error::Capacity(tungstenite::error::CapacityError::TooManyHeaders) => {
                unreachable!("headers are not sent after handshake")
            }
        }
    }
}
/// The subset of [`tungstenite::Error`] values that can be produced by a
/// connected websocket.
///
/// This is the union of [`TungsteniteSendError`] and
/// [`TungsteniteReceiveError`]. It is split out as a separate type to reduce
/// duplication for error [`tungstenite::Error`] cases that don't appear when
/// sending or receiving on a connected websocket.
enum TungsteniteError {
    ConnectionClosed,
    AlreadyClosed,
    Io(IoError),
    CapacityErrorMessageTooLarge { size: usize, max_size: usize },
    Protocol(tungstenite::error::ProtocolError),
    WriteBufferFull,
    Utf8,
}

#[cfg(test)]
mod test {
    use std::future::Future;
    use std::io::ErrorKind as IoErrorKind;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use assert_matches::assert_matches;
    use futures_util::{pin_mut, FutureExt as _};
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    use super::*;
    use crate::testutil::TestStream;
    use crate::utils::testutil::TestWaker;

    /// A long enough period of time that it's functionally "forever".
    const FOREVER: Duration = Duration::from_secs(10000000000);

    #[tokio::test(start_paused = true)]
    async fn sends_outgoing_messages() {
        let (mut ws_server, ws_client) = TestStream::new_pair(1);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(1);
        let connection = Connection::new(
            ws_client,
            ReceiverStream::new(outgoing_rx),
            Config {
                local_idle_timeout: FOREVER,
                remote_idle_ping_timeout: FOREVER,
                remote_idle_disconnect_timeout: FOREVER,
            },
            "test".into(),
        );
        pin_mut!(connection);

        const SENT_MESSAGE: &str = "client-sent message";
        const SENT_META: u32 = 123456;

        let sent_message = TextOrBinary::Text(SENT_MESSAGE.to_string());
        outgoing_tx
            .send((sent_message.clone(), SENT_META))
            .await
            .expect("can send to connection");

        let result = connection.handle_next_event().await;
        assert_matches!(
            result,
            Outcome::Continue(MessageEvent::SentMessage(SENT_META))
        );
        assert_matches!(
            ws_server.next().now_or_never(),
            Some(Some(Ok(Message::Text(text)))) if text == SENT_MESSAGE
        );
    }

    #[tokio::test(start_paused = true)]
    async fn receives_incoming_messages() {
        let (mut ws_server, ws_client) = TestStream::new_pair(5);
        let outgoing_rx = futures_util::stream::pending::<(_, ())>();
        let connection = Connection::new(
            ws_client,
            outgoing_rx,
            Config {
                local_idle_timeout: FOREVER,
                remote_idle_ping_timeout: FOREVER,
                remote_idle_disconnect_timeout: FOREVER,
            },
            "test".into(),
        );
        pin_mut!(connection);

        ws_server
            .send_all(
                &mut futures_util::stream::iter([
                    Message::Text("first message".to_string()),
                    Message::Binary(b"second message".into()),
                    Message::Ping(vec![1, 2, 3]),
                    Message::Pong(vec![1, 2, 3]),
                    Message::Close(None),
                ])
                .map(Ok),
            )
            .await
            .expect("can send all");

        assert_matches!(
            connection.as_mut().handle_next_event().await,
            Outcome::Continue(MessageEvent::ReceivedMessage(TextOrBinary::Text(text))) if text == "first message");
        assert_matches!(
            connection.as_mut().handle_next_event().await,
            Outcome::Continue(MessageEvent::ReceivedMessage(TextOrBinary::Binary(bin))) if bin == b"second message");
        assert_matches!(
            connection.as_mut().handle_next_event().await,
            Outcome::Continue(MessageEvent::ReceivedPingPong)
        );
        assert_matches!(
            connection.as_mut().handle_next_event().await,
            Outcome::Continue(MessageEvent::ReceivedPingPong)
        );
        assert_matches!(
            connection.as_mut().handle_next_event().await,
            Outcome::Finished(Ok(FinishReason::RemoteDisconnect))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn handles_error_on_failed_send() {
        let (ws_server, ws_client) = TestStream::new_pair(1);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(2);
        let connection = Connection::new(
            ws_client,
            ReceiverStream::new(outgoing_rx),
            Config {
                local_idle_timeout: FOREVER,
                remote_idle_ping_timeout: FOREVER,
                remote_idle_disconnect_timeout: FOREVER,
            },
            "test".into(),
        );
        pin_mut!(connection);

        // The first send will succeed but the second one will fail once the
        // receiver is dropped.

        outgoing_tx
            .send(("successfully sent".to_string().into(), ()))
            .await
            .expect("can send");
        outgoing_tx
            .send(("fail to sent".to_string().into(), ()))
            .await
            .expect("can send");

        assert_matches!(
            connection.as_mut().handle_next_event().await,
            Outcome::Continue(_)
        );

        let second_send = connection.as_mut().handle_next_event();
        // Limit the lifetime of second_send by pinning it inside this block.
        // The value won't get dropped until the end of the block, so without
        // this the reference to `connection` below would be a second mutable
        // borrow.
        {
            pin_mut!(second_send);

            // This should start sending but won't be able to complete since there
            // isn't enough space in the client websocket stream.
            assert_matches!(
                second_send
                    .as_mut()
                    .poll(&mut Context::from_waker(&TestWaker::as_waker(
                        &Arc::default()
                    ))),
                Poll::Pending
            );

            // Hang up on the client. When the paused send is interrupted, it should
            // return an error.
            drop(ws_server);
            assert_matches!(
                second_send.await,
                Outcome::Continue(MessageEvent::SendFailed((), TungsteniteSendError::Io(_)))
            );
        }

        // Since the server hung up, the client should now be done.
        assert_matches!(
            connection.handle_next_event().await,
            Outcome::Finished(Err(NextEventError::UnexpectedConnectionClose))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn terminates_gracefully_after_outgoing_close() {
        let (_ws_server, ws_client) = TestStream::new_pair(1);
        let (outgoing_tx, outgoing_rx) = mpsc::channel::<(_, ())>(1);
        let connection = Connection::new(
            ws_client,
            ReceiverStream::new(outgoing_rx),
            Config {
                local_idle_timeout: FOREVER,
                remote_idle_ping_timeout: FOREVER,
                remote_idle_disconnect_timeout: FOREVER,
            },
            "test".into(),
        );
        pin_mut!(connection);

        drop(outgoing_tx);
        assert_matches!(
            connection.handle_next_event().await,
            Outcome::Finished(Ok(FinishReason::LocalDisconnect))
        )
    }

    #[tokio::test(start_paused = true)]
    async fn handles_remote_close_with_error() {
        let (mut ws_server, ws_client) = TestStream::new_pair(5);
        let outgoing_rx = futures_util::stream::pending::<(_, ())>();
        let connection = Connection::new(
            ws_client,
            outgoing_rx,
            Config {
                local_idle_timeout: FOREVER,
                remote_idle_ping_timeout: FOREVER,
                remote_idle_disconnect_timeout: FOREVER,
            },
            "test".into(),
        );
        pin_mut!(connection);

        ws_server
            .send(Message::Close(Some(CloseFrame {
                code: CloseCode::Away,
                reason: "and don't come back".into(),
            })))
            .await
            .expect("can send");

        assert_matches!(
            connection.as_mut().handle_next_event().await,
            Outcome::Finished(Err(NextEventError::AbnormalServerClose {
                code: CloseCode::Away,
                ..
            }))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn handles_error_from_remote() {
        let (mut ws_server, ws_client) = TestStream::new_pair(5);
        let outgoing_rx = futures_util::stream::pending::<(_, ())>();
        let connection = Connection::new(
            ws_client,
            outgoing_rx,
            Config {
                local_idle_timeout: FOREVER,
                remote_idle_ping_timeout: FOREVER,
                remote_idle_disconnect_timeout: FOREVER,
            },
            "test".into(),
        );
        pin_mut!(connection);

        ws_server
            .send_error(tungstenite::Error::Io(IoError::new(
                IoErrorKind::ConnectionReset,
                "reset",
            )))
            .await
            .expect("can send");

        assert_matches!(
            connection.as_mut().handle_next_event().await,
            Outcome::Finished(Err(NextEventError::ReceiveError(TungsteniteReceiveError::Io(err))))
            if err.kind() == IoErrorKind::ConnectionReset);
    }

    #[tokio::test(start_paused = true)]
    async fn sends_ping_after_local_inactivity() {
        const LOCAL_IDLE_TIMEOUT: Duration = Duration::from_secs(123);

        let (mut ws_server, ws_client) = TestStream::new_pair(1);
        let outgoing_rx = futures_util::stream::pending::<(_, ())>();
        let connection = Connection::new(
            ws_client,
            outgoing_rx,
            Config {
                local_idle_timeout: LOCAL_IDLE_TIMEOUT,
                remote_idle_ping_timeout: FOREVER,
                remote_idle_disconnect_timeout: FOREVER,
            },
            "test".into(),
        );
        pin_mut!(connection);

        // Without anything in the incoming pipe, this should time out after the
        // specified idle time.
        let start = Instant::now();
        let result = connection.as_mut().handle_next_event().await;

        assert_eq!(Instant::now() - start, LOCAL_IDLE_TIMEOUT);
        assert_matches!(result, Outcome::Continue(MessageEvent::SentPing));

        let first_ping = ws_server.next().now_or_never().expect("now");
        let first_ping =
            assert_matches!(first_ping, Some(Ok(message @ Message::Ping(_))) => message);

        // After some more time passes, another ping should be sent. It should
        // be different from the first!
        let result = connection.handle_next_event().await;
        assert_matches!(result, Outcome::Continue(MessageEvent::SentPing));

        let second_ping = ws_server.next().now_or_never().expect("now");
        let second_ping =
            assert_matches!(second_ping, Some(Ok(message @ Message::Ping(_))) => message);
        assert_ne!(first_ping, second_ping);
    }

    #[tokio::test(start_paused = true)]
    async fn sends_ping_after_remote_inactivity_then_time_out() {
        // A single ping will be sent locally before the server times out.
        const REMOTE_IDLE_PING_TIMEOUT: Duration = Duration::from_secs(12);
        const REMOTE_DISCONNECT_TIMEOUT: Duration = Duration::from_secs(20);

        let (_ws_server, ws_client) = TestStream::new_pair(10);
        let outgoing_rx = futures_util::stream::pending::<(_, ())>();
        let connection = Connection::new(
            ws_client,
            outgoing_rx,
            Config {
                remote_idle_ping_timeout: REMOTE_IDLE_PING_TIMEOUT,
                remote_idle_disconnect_timeout: REMOTE_DISCONNECT_TIMEOUT,
                local_idle_timeout: FOREVER,
            },
            "test".into(),
        );
        pin_mut!(connection);

        let start = Instant::now();
        // The ping timeout gets hit first.
        let result = connection.as_mut().handle_next_event().await;
        assert_eq!(Instant::now() - start, REMOTE_IDLE_PING_TIMEOUT);
        assert_matches!(result, Outcome::Continue(MessageEvent::SentPing));

        // The server never responds so the call times out.
        let result = connection.handle_next_event().await;
        assert_matches!(
            result,
            Outcome::Finished(Err(NextEventError::ServerIdleTimeout(
                REMOTE_DISCONNECT_TIMEOUT
            )))
        );
        assert_eq!(Instant::now() - start, REMOTE_DISCONNECT_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn incoming_message_resets_server_timeout() {
        const REMOTE_IDLE_TIMEOUT: Duration = Duration::from_secs(20);
        const REMOTE_DISCONNECT_TIMEOUT: Duration = Duration::from_secs(30);

        let (mut ws_server, ws_client) = TestStream::new_pair(10);
        let (outgoing_tx, outgoing_rx) = mpsc::channel(1);
        let connection = Connection::new(
            ws_client,
            ReceiverStream::new(outgoing_rx),
            Config {
                local_idle_timeout: FOREVER,
                remote_idle_ping_timeout: REMOTE_IDLE_TIMEOUT,
                remote_idle_disconnect_timeout: REMOTE_DISCONNECT_TIMEOUT,
            },
            "test".into(),
        );
        pin_mut!(connection);

        let handle_first = connection.as_mut().handle_next_event();

        // After the client waits for a while, the server sends a message before
        // the timeout. That resets the remote idle timeout.
        let (_sleep_then_send, result) = tokio::join!(
            async {
                tokio::time::sleep(REMOTE_IDLE_TIMEOUT / 2).await;
                ws_server
                    .send(Message::Text("from server".to_string()))
                    .await
                    .expect("can send from server");
            },
            handle_first
        );
        assert_matches!(result, Outcome::Continue(MessageEvent::ReceivedMessage(_)));
        let server_last_seen_at = Instant::now();

        tokio::time::advance(REMOTE_IDLE_TIMEOUT / 2).await;
        // The client sends a message, but that doesn't reset the remote timeout.
        outgoing_tx
            .send((TextOrBinary::Text("from the client".to_string()), ()))
            .await
            .expect("can send to connection");
        let result = connection
            .as_mut()
            .handle_next_event()
            .now_or_never()
            .expect("sent message");
        assert_matches!(result, Outcome::Continue(MessageEvent::SentMessage(())));

        // The server isn't saying anything so we send a ping.
        let result = connection.as_mut().handle_next_event().await;
        assert_eq!(Instant::now() - server_last_seen_at, REMOTE_IDLE_TIMEOUT);
        assert_matches!(result, Outcome::Continue(MessageEvent::SentPing));

        // The server still doesn't respond, so after a longer period of time we disconnect.
        let result = connection.as_mut().handle_next_event().await;
        assert_matches!(
            result,
            Outcome::Finished(Err(NextEventError::ServerIdleTimeout(
                REMOTE_DISCONNECT_TIMEOUT
            )))
        );
        assert_eq!(
            Instant::now() - server_last_seen_at,
            REMOTE_DISCONNECT_TIMEOUT
        );
    }
}
