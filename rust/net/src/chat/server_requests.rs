//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures_util::future::BoxFuture;
use futures_util::Stream;
use libsignal_net_infra::ws::WebSocketServiceError;
use libsignal_net_infra::AsyncDuplexStream;
use libsignal_protocol::Timestamp;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt as _;

use crate::chat::ws::ServerEvent as WsServerEvent;
use crate::chat::{ws2, ChatServiceError, RequestProto};
use crate::env::TIMESTAMP_HEADER_NAME;

pub type ResponseEnvelopeSender = Box<
    dyn FnOnce(http::StatusCode) -> BoxFuture<'static, Result<(), ChatServiceError>> + Send + Sync,
>;

pub enum ServerEvent {
    QueueEmpty,
    IncomingMessage {
        request_id: u64,
        envelope: Vec<u8>,
        server_delivery_timestamp: Timestamp,
        send_ack: ResponseEnvelopeSender,
    },
    Stopped(ChatServiceError),
}

impl std::fmt::Debug for ServerEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueueEmpty => write!(f, "QueueEmpty"),
            Self::IncomingMessage {
                envelope,
                server_delivery_timestamp,
                request_id,
                send_ack: _,
            } => f
                .debug_struct("IncomingMessage")
                .field("request_id", request_id)
                .field("envelope", &format_args!("{} bytes", envelope.len()))
                .field("server_delivery_timestamp", server_delivery_timestamp)
                .finish(),
            Self::Stopped(error) => f
                .debug_struct("ConnectionInterrupted")
                .field("reason", error)
                .finish(),
        }
    }
}

#[derive(Debug)]
pub enum ServerEventError {
    UnexpectedVerb(String),
    MissingPath,
    UnrecognizedPath(String),
}

pub fn stream_incoming_messages(
    receiver: mpsc::Receiver<WsServerEvent<impl AsyncDuplexStream + 'static>>,
) -> impl Stream<Item = ServerEvent> {
    ReceiverStream::new(receiver).filter_map(|request| match request.try_into() {
        Ok(request) => Some(request),
        Err(e) => {
            match e {
                ServerEventError::UnexpectedVerb(verb) => {
                    log::error!("server request used unexpected verb {verb}",);
                }
                ServerEventError::MissingPath => {
                    log::error!("server request missing path");
                }
                ServerEventError::UnrecognizedPath(unknown_path) => {
                    log::error!("server sent an unknown request: {unknown_path}");
                }
            };
            None
        }
    })
}

impl TryFrom<ws2::ListenerEvent> for ServerEvent {
    type Error = ServerEventError;

    fn try_from(value: ws2::ListenerEvent) -> Result<Self, Self::Error> {
        match value {
            ws2::ListenerEvent::ReceivedMessage(proto, responder) => {
                convert_received_message(proto, || {
                    Box::new(move |status| {
                        // TODO remove this async when it's no longer necessary.
                        Box::pin(async move { Ok(responder.send_response(status)?) })
                    })
                })
            }

            ws2::ListenerEvent::Finished(reason) => Ok(ServerEvent::Stopped(match reason {
                Ok(ws2::FinishReason::LocalDisconnect) => {
                    ChatServiceError::ServiceIntentionallyDisconnected
                }
                Ok(ws2::FinishReason::RemoteDisconnect) => {
                    ChatServiceError::WebSocket(WebSocketServiceError::ChannelClosed)
                }
                Err(ws2::FinishError::Unknown) => {
                    ChatServiceError::WebSocket(WebSocketServiceError::Other("unexpected exit"))
                }
                Err(ws2::FinishError::Error(e)) => e.into(),
            })),
        }
    }
}

impl<S: AsyncDuplexStream + 'static> TryFrom<WsServerEvent<S>> for ServerEvent {
    type Error = ServerEventError;

    fn try_from(value: WsServerEvent<S>) -> Result<Self, Self::Error> {
        match value {
            WsServerEvent::Stopped(error) => Ok(ServerEvent::Stopped(error)),
            WsServerEvent::Request {
                request_proto,
                response_sender,
            } => convert_received_message(request_proto, || {
                Box::new(|status| Box::pin(response_sender.send_response(status)))
            }),
        }
    }
}

fn convert_received_message(
    proto: crate::proto::chat_websocket::WebSocketRequestMessage,
    make_send_ack: impl FnOnce() -> ResponseEnvelopeSender,
) -> Result<ServerEvent, ServerEventError> {
    let RequestProto {
        verb,
        path,
        body,
        headers,
        id,
    } = proto;
    let verb = verb.unwrap_or_default();
    if verb != http::Method::PUT.as_str() {
        return Err(ServerEventError::UnexpectedVerb(verb));
    }

    let path = path.unwrap_or_default();
    match &*path {
        "/api/v1/queue/empty" => Ok(ServerEvent::QueueEmpty),
        "/api/v1/message" => {
            let raw_timestamp = headers
                .iter()
                .filter_map(|header| {
                    let (name, value) = header.split_once(':')?;
                    if name.eq_ignore_ascii_case(TIMESTAMP_HEADER_NAME) {
                        value.trim().parse::<u64>().ok()
                    } else {
                        None
                    }
                })
                .last();
            if raw_timestamp.is_none() {
                log::warn!("server delivered message with no {TIMESTAMP_HEADER_NAME} header");
            }
            let request_id = id.unwrap_or(0);

            // We don't check whether the body is missing here. The consumer still needs to ack
            // malformed envelopes, or they'd be delivered over and over, and an empty envelope
            // is just a special case of a malformed envelope.
            Ok(ServerEvent::IncomingMessage {
                request_id,
                envelope: body.unwrap_or_default(),
                server_delivery_timestamp: Timestamp::from_epoch_millis(
                    raw_timestamp.unwrap_or_default(),
                ),
                send_ack: make_send_ack(),
            })
        }
        "" => Err(ServerEventError::MissingPath),
        _unknown_path => Err(ServerEventError::UnrecognizedPath(path)),
    }
}
