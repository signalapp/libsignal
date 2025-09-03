//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use bytes::Bytes;
use libsignal_net_infra::ws::WebSocketError;
use libsignal_protocol::Timestamp;

use crate::chat::{RequestProto, SendError, ws};
use crate::env::TIMESTAMP_HEADER_NAME;

pub type ResponseEnvelopeSender =
    Box<dyn FnOnce(http::StatusCode) -> Result<(), SendError> + Send + Sync>;

pub enum ServerEvent {
    QueueEmpty,
    IncomingMessage {
        request_id: u64,
        envelope: Bytes,
        server_delivery_timestamp: Timestamp,
        send_ack: ResponseEnvelopeSender,
    },
    Alerts(Vec<String>),
    Stopped(DisconnectCause),
}

#[derive(Debug, derive_more::From)]
pub enum DisconnectCause {
    LocalDisconnect,
    Error(#[from] SendError),
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
            Self::Alerts(alerts) => f.debug_tuple("Alerts").field(&alerts.len()).finish(),
            Self::Stopped(error) => f
                .debug_struct("ConnectionInterrupted")
                .field("reason", error)
                .finish(),
        }
    }
}

#[derive(Debug, displaydoc::Display)]
pub enum ServerEventError {
    /// server request used unexpected verb {0}
    UnexpectedVerb(String),
    /// server request missing path
    MissingPath,
    /// server sent an unknown request: {0}
    UnrecognizedPath(String),
}

impl TryFrom<ws::ListenerEvent> for ServerEvent {
    type Error = ServerEventError;

    fn try_from(value: ws::ListenerEvent) -> Result<Self, Self::Error> {
        match value {
            ws::ListenerEvent::ReceivedAlerts(alerts) => Ok(Self::Alerts(alerts)),

            ws::ListenerEvent::ReceivedMessage(proto, responder) => {
                convert_received_message(proto, |timestamp| {
                    Box::new(move |status| {
                        log::info!(
                            "ACKing message delivered at {} (not a message ID)",
                            timestamp.epoch_millis()
                        );
                        Ok(responder.send_response(status)?)
                    })
                })
            }

            ws::ListenerEvent::Finished(reason) => Ok(ServerEvent::Stopped(match reason {
                Ok(ws::FinishReason::LocalDisconnect) => DisconnectCause::LocalDisconnect,
                Ok(ws::FinishReason::RemoteDisconnect) => {
                    DisconnectCause::Error(SendError::WebSocket(WebSocketError::ChannelClosed))
                }
                Err(ws::FinishError::Unknown) => DisconnectCause::Error(SendError::WebSocket(
                    WebSocketError::Other("unexpected exit"),
                )),
                Err(ws::FinishError::Error(e)) => DisconnectCause::Error(e.into()),
            })),
        }
    }
}

fn convert_received_message(
    proto: crate::proto::chat_websocket::WebSocketRequestMessage,
    make_send_ack: impl FnOnce(Timestamp) -> ResponseEnvelopeSender,
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
        "/api/v1/queue/empty" => {
            log::info!("received queue empty notification");
            Ok(ServerEvent::QueueEmpty)
        }
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
                .next_back();

            if let Some(raw_timestamp) = raw_timestamp {
                log::info!(
                    "received message at {TIMESTAMP_HEADER_NAME}: {raw_timestamp} (this is not a message ID)"
                );
            } else {
                log::warn!("server delivered message with no valid {TIMESTAMP_HEADER_NAME} header");
            }

            let request_id = id.unwrap_or(0);
            let server_delivery_timestamp =
                Timestamp::from_epoch_millis(raw_timestamp.unwrap_or_default());

            // We don't check whether the body is missing here. The consumer still needs to ack
            // malformed envelopes, or they'd be delivered over and over, and an empty envelope
            // is just a special case of a malformed envelope.
            Ok(ServerEvent::IncomingMessage {
                request_id,
                envelope: body.unwrap_or_default(),
                server_delivery_timestamp,
                send_ack: make_send_ack(server_delivery_timestamp),
            })
        }
        "" => Err(ServerEventError::MissingPath),
        _unknown_path => Err(ServerEventError::UnrecognizedPath(path)),
    }
}
