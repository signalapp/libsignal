//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use bytes::Bytes;
use libsignal_net_infra::ws::WebSocketError;
use libsignal_protocol::Timestamp;
use prost::Message;

use crate::chat::{RequestProto, SendError, ws};
use crate::env::TIMESTAMP_HEADER_NAME;
use crate::proto::chat_provisioning as pb;

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
    /// could not parse server request body
    MalformedBody,
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

            ws::ListenerEvent::Finished(reason) => {
                Ok(ServerEvent::Stopped(convert_finished_reason(reason)))
            }
        }
    }
}

fn convert_finished_reason(reason: Result<ws::FinishReason, ws::FinishError>) -> DisconnectCause {
    match reason {
        Ok(ws::FinishReason::LocalDisconnect) => DisconnectCause::LocalDisconnect,
        Ok(ws::FinishReason::RemoteDisconnect) => {
            DisconnectCause::Error(SendError::WebSocket(WebSocketError::ChannelClosed))
        }
        Err(ws::FinishError::Unknown) => DisconnectCause::Error(SendError::WebSocket(
            WebSocketError::Other("unexpected exit"),
        )),
        Err(ws::FinishError::Error(e)) => DisconnectCause::Error(e.into()),
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

pub enum ProvisioningEvent {
    ReceivedAddress {
        address: String,
        send_ack: ResponseEnvelopeSender,
    },
    ReceivedEnvelope {
        envelope: Bytes,
        send_ack: ResponseEnvelopeSender,
    },
    Stopped(DisconnectCause),
}

impl std::fmt::Debug for ProvisioningEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ReceivedAddress {
                address: _,
                send_ack: _,
            } => f
                .debug_tuple("ReceivedAddress")
                .field(&"<address>")
                .finish(),
            Self::ReceivedEnvelope {
                envelope,
                send_ack: _,
            } => f
                .debug_tuple("ReceivedEnvelope")
                .field(&format_args!("{} bytes", envelope.len()))
                .finish(),
            Self::Stopped(error) => f
                .debug_struct("ConnectionInterrupted")
                .field("reason", error)
                .finish(),
        }
    }
}

impl TryFrom<ws::ListenerEvent> for ProvisioningEvent {
    type Error = ServerEventError;

    fn try_from(value: ws::ListenerEvent) -> Result<Self, Self::Error> {
        match value {
            // Provisioning shouldn't have alerts; produce an error if it does.
            ws::ListenerEvent::ReceivedAlerts(_alerts) => Err(ServerEventError::UnrecognizedPath(
                crate::env::ALERT_HEADER_NAME.to_owned(),
            )),

            ws::ListenerEvent::ReceivedMessage(proto, responder) => {
                let RequestProto {
                    verb,
                    path,
                    body,
                    headers: _,
                    id: _,
                } = proto;
                let verb = verb.unwrap_or_default();
                if verb != http::Method::PUT.as_str() {
                    return Err(ServerEventError::UnexpectedVerb(verb));
                }

                let path = path.unwrap_or_default();
                match &*path {
                    "/v1/address" => {
                        let proto = pb::ProvisioningAddress::decode(body.unwrap_or_default())
                            .map_err(|_| ServerEventError::MalformedBody)?;
                        Ok(ProvisioningEvent::ReceivedAddress {
                            address: proto.address.unwrap_or_default(),
                            send_ack: Box::new(move |status| {
                                log::info!("acknowledging provisioning address with {status}");
                                Ok(responder.send_response(status)?)
                            }),
                        })
                    }
                    "/v1/message" => Ok(ProvisioningEvent::ReceivedEnvelope {
                        envelope: body.unwrap_or_default(),
                        send_ack: Box::new(move |status| {
                            log::info!("acknowledging provisioning envelope with {status}");
                            Ok(responder.send_response(status)?)
                        }),
                    }),
                    "" => Err(ServerEventError::MissingPath),
                    _unknown_path => Err(ServerEventError::UnrecognizedPath(path)),
                }
            }

            ws::ListenerEvent::Finished(reason) => {
                Ok(ProvisioningEvent::Stopped(convert_finished_reason(reason)))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use test_case::test_case;

    use super::*;
    use crate::proto::chat_websocket::WebSocketRequestMessage;

    #[test]
    fn provisioning_address() {
        const ADDRESS: &str = "addr-for-qr-code";
        let event = ProvisioningEvent::try_from(ws::ListenerEvent::ReceivedMessage(
            WebSocketRequestMessage {
                verb: Some("PUT".to_owned()),
                path: Some("/v1/address".to_owned()),
                body: Some(
                    pb::ProvisioningAddress {
                        address: Some(ADDRESS.to_owned()),
                    }
                    .encode_to_vec()
                    .into(),
                ),
                headers: vec![],
                id: Some(1),
            },
            ws::Responder::dummy(),
        ))
        .expect("valid");
        assert_matches!(event, ProvisioningEvent::ReceivedAddress { address, .. } if address == ADDRESS);
    }

    #[test]
    fn provisioning_envelope() {
        const BODY: &[u8] = b"encoded provisioning envelope";
        let event = ProvisioningEvent::try_from(ws::ListenerEvent::ReceivedMessage(
            WebSocketRequestMessage {
                verb: Some("PUT".to_owned()),
                path: Some("/v1/message".to_owned()),
                body: Some(BODY.into()),
                headers: vec![],
                id: Some(1),
            },
            ws::Responder::dummy(),
        ))
        .expect("valid");
        assert_matches!(event, ProvisioningEvent::ReceivedEnvelope { envelope, .. } if envelope == BODY);
    }

    #[test_case(WebSocketRequestMessage {
        verb: Some("GET".to_owned()),
        path: Some("/v1/message".to_owned()),
        ..Default::default()
    } => matches ServerEventError::UnexpectedVerb(verb) if verb == "GET")]
    #[test_case(WebSocketRequestMessage {
        verb: Some("PUT".to_owned()),
        path: Some("/v1/address".to_owned()),
        body: Some(b"not valid protobuf"[..].into()),
        ..Default::default()
    } => matches ServerEventError::MalformedBody)]
    #[test_case(WebSocketRequestMessage {
        verb: Some("PUT".to_owned()),
        ..Default::default()
    } => matches ServerEventError::MissingPath)]
    #[test_case(WebSocketRequestMessage {
        verb: Some("PUT".to_owned()),
        path: Some("/absolute-nonsense".to_owned()),
        ..Default::default()
    } => matches ServerEventError::UnrecognizedPath(path) if path == "/absolute-nonsense")]
    fn malformed_provisioning_events(message: WebSocketRequestMessage) -> ServerEventError {
        ProvisioningEvent::try_from(ws::ListenerEvent::ReceivedMessage(
            message,
            ws::Responder::dummy(),
        ))
        .expect_err("malformed")
    }
}
