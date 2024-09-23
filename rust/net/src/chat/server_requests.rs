//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures_util::future::BoxFuture;
use futures_util::Stream;
use libsignal_net_infra::AsyncDuplexStream;
use libsignal_protocol::Timestamp;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt as _;

use crate::chat::ws::ServerEvent as WsServerEvent;
use crate::chat::ChatServiceError;
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

pub fn stream_incoming_messages(
    receiver: mpsc::Receiver<WsServerEvent<impl AsyncDuplexStream + 'static>>,
) -> impl Stream<Item = ServerEvent> {
    ReceiverStream::new(receiver).filter_map(|request| match request {
        WsServerEvent::Stopped(error) => Some(ServerEvent::Stopped(error)),
        WsServerEvent::Request {
            request_proto,
            response_sender,
        } => {
            if request_proto.verb() != http::Method::PUT.as_str() {
                log::error!(
                    "server request used unexpected verb {}",
                    request_proto.verb()
                );
                return None;
            }

            let message = match request_proto.path.as_deref().unwrap_or_default() {
                "/api/v1/queue/empty" => ServerEvent::QueueEmpty,
                "/api/v1/message" => {
                    let raw_timestamp = request_proto
                        .headers
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
                        log::warn!(
                            "server delivered message with no {TIMESTAMP_HEADER_NAME} header"
                        );
                    }

                    // We don't check whether the body is missing here. The consumer still needs to ack
                    // malformed envelopes, or they'd be delivered over and over, and an empty envelope
                    // is just a special case of a malformed envelope.
                    ServerEvent::IncomingMessage {
                        request_id: request_proto.id(),
                        envelope: request_proto.body.unwrap_or_default(),
                        server_delivery_timestamp: Timestamp::from_epoch_millis(
                            raw_timestamp.unwrap_or_default(),
                        ),
                        send_ack: Box::new(|status| {
                            Box::pin(response_sender.send_response(status))
                        }),
                    }
                }
                "" => {
                    log::error!("server request missing path");
                    return None;
                }
                unknown_path => {
                    log::error!("server sent an unknown request: {unknown_path}");
                    return None;
                }
            };
            Some(message)
        }
    })
}
