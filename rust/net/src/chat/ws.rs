//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt, TryFutureExt};
use prost::Message;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::Instant;
use tungstenite::protocol::WebSocketConfig;

use crate::chat::errors::ChatNetworkError;
use crate::chat::{ChatMessageType, ChatService, MessageProto, RequestProto, ResponseProto};
use crate::env::constants::WEB_SOCKET_PATH;
use crate::infra::reconnect::{ServiceConnector, ServiceStatus};
use crate::infra::ws::{connect_websocket, WebSocketStream};
use crate::infra::ConnectionParams;
use crate::utils::timeout;

#[derive(Default, Eq, Hash, PartialEq, Clone, Copy)]
struct RequestId {
    id: u64,
}

impl RequestId {
    fn new(id: u64) -> Self {
        Self { id }
    }
}

enum ChatMessage {
    Request(RequestProto),
    Response(RequestId, ResponseProto),
}

pub struct ServerRequest {
    request_proto: RequestProto,
    outgoing_tx: mpsc::Sender<Vec<u8>>,
}

impl ServerRequest {
    fn new(request_proto: RequestProto, outgoing_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            request_proto,
            outgoing_tx,
        }
    }

    pub async fn send_response(
        &self,
        code: http::status::StatusCode,
    ) -> Result<(), ChatNetworkError> {
        let id = self
            .request_proto
            .id
            .ok_or(ChatNetworkError::ServerRequestMissingId)?;
        let response = response_for_code(id, code);
        self.outgoing_tx
            .send(message_to_vec(ChatMessage::Response(
                RequestId::default(),
                response,
            )))
            .await
            .map_err(|_| ChatNetworkError::FailedToPassMessageToSenderTask)
    }
}

#[derive(Debug, Clone)]
pub struct ChatOverWebsocketConfig {
    pub ws_config: WebSocketConfig,
    pub endpoint: http::uri::PathAndQuery,
    pub max_connection_time: Duration,
    pub keep_alive_interval: Duration,
    pub max_idle_time: Duration,
    pub incoming_messages_queue_size: usize,
    pub outgoing_messages_queue_size: usize,
}

impl Default for ChatOverWebsocketConfig {
    fn default() -> Self {
        Self {
            ws_config: WebSocketConfig::default(),
            endpoint: http::uri::PathAndQuery::from_static(WEB_SOCKET_PATH),
            max_connection_time: Duration::from_secs(1),
            keep_alive_interval: Duration::from_secs(5),
            max_idle_time: Duration::from_secs(15),
            incoming_messages_queue_size: 1024,
            outgoing_messages_queue_size: 256,
        }
    }
}

type PendingMessagesMap = HashMap<RequestId, oneshot::Sender<ResponseProto>>;

#[derive(Clone)]
pub struct ChatOverWebSocketServiceConnector {
    config: ChatOverWebsocketConfig,
    incoming_tx: mpsc::Sender<ServerRequest>,
}

impl ChatOverWebSocketServiceConnector {
    pub fn new(config: ChatOverWebsocketConfig, incoming_tx: mpsc::Sender<ServerRequest>) -> Self {
        Self {
            config,
            incoming_tx,
        }
    }
}

#[async_trait]
impl ServiceConnector for ChatOverWebSocketServiceConnector {
    type Service = ChatOverWebSocket;
    type Channel = WebSocketStream;
    type Error = ChatNetworkError;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::Error> {
        let connect_future = connect_websocket(
            connection_params,
            self.config.endpoint.clone(),
            self.config.ws_config,
        )
        .map_err(|_| ChatNetworkError::FailedToConnectWebSocket);
        timeout(
            self.config.max_connection_time,
            ChatNetworkError::Timeout,
            connect_future,
        )
        .await
    }

    fn start_service(&self, channel: Self::Channel) -> (Self::Service, ServiceStatus<Self::Error>) {
        let (outgoing_tx, outgoing_rx) =
            mpsc::channel::<Vec<u8>>(self.config.outgoing_messages_queue_size);
        let service_status = ServiceStatus::new();
        let (ws_outgoing, ws_incoming) = channel.split();
        let pending_messages: Arc<Mutex<PendingMessagesMap>> = Default::default();
        tokio::spawn(reader_task(
            ws_incoming,
            self.config.max_idle_time,
            pending_messages.clone(),
            self.incoming_tx.clone(),
            outgoing_tx.clone(),
            service_status.clone(),
        ));
        tokio::spawn(writer_task(
            ws_outgoing,
            self.config.keep_alive_interval,
            outgoing_rx,
            service_status.clone(),
        ));
        (
            ChatOverWebSocket {
                outgoing_tx,
                service_status: service_status.clone(),
                pending_messages,
            },
            service_status,
        )
    }
}

#[derive(Clone)]
pub struct ChatOverWebSocket {
    outgoing_tx: mpsc::Sender<Vec<u8>>,
    service_status: ServiceStatus<ChatNetworkError>,
    pending_messages: Arc<Mutex<PendingMessagesMap>>,
}

#[async_trait]
impl ChatService for ChatOverWebSocket {
    async fn send(
        &mut self,
        msg: &MessageProto,
        timeout: Duration,
    ) -> Result<ResponseProto, ChatNetworkError> {
        let req = msg
            .request
            .as_ref()
            .ok_or(ChatNetworkError::UnexpectedMessageType)?;

        // checking if channel has been closed
        if self.service_status.is_stopped() {
            return Err(ChatNetworkError::ChannelClosed);
        }

        // `id` must be present on the request object
        let id = RequestId::new(req.id.ok_or(ChatNetworkError::RequestMissingId)?);

        let (response_tx, response_rx) = oneshot::channel::<ResponseProto>();

        // defining a scope here to release the lock ASAP
        {
            let map = &mut self.pending_messages.lock().await;
            if map.contains_key(&id) {
                return Err(ChatNetworkError::RequestIdCollision);
            }
            map.insert(id, response_tx);
        }

        self.outgoing_tx
            .send(msg.encode_to_vec())
            .await
            .map_err(|_| ChatNetworkError::FailedToPassMessageToSenderTask)?;

        let res = tokio::select! {
            result = response_rx => Ok(result.expect("sender is not dropped before receiver")),
            _ = tokio::time::sleep(timeout) => Err(ChatNetworkError::Timeout),
            _ = self.service_status.stopped() => Err(ChatNetworkError::ChannelClosed)
        };
        if res.is_err() {
            // in case of an error we need to clean up the listener from the `pending_messages` map
            let map = &mut self.pending_messages.lock().await;
            map.remove(&id);
        }
        res
    }
}

async fn writer_task(
    mut ws_stream: SplitSink<WebSocketStream, tungstenite::Message>,
    keep_alive_interval: Duration,
    mut outgoing_rx: mpsc::Receiver<Vec<u8>>,
    service_status: ServiceStatus<ChatNetworkError>,
) {
    // events specific to the logic within this method
    enum Event {
        Message(Option<Vec<u8>>),
        KeepAlive,
        Cancellation,
    }
    loop {
        match tokio::select! {
            maybe_msg = outgoing_rx.recv() => Event::Message(maybe_msg),
            _ = tokio::time::sleep(keep_alive_interval) => Event::KeepAlive,
            _ = service_status.stopped() => Event::Cancellation,
        } {
            Event::Message(Some(msg)) => {
                send_and_validate(
                    &mut ws_stream,
                    tungstenite::Message::binary(msg),
                    &service_status,
                )
                .await;
            }
            Event::Message(None) => {
                // looks like all possible publishers are dropped,
                // channel can be closed
                service_status.stop_service();
                break;
            }
            Event::KeepAlive => {
                send_and_validate(
                    &mut ws_stream,
                    tungstenite::Message::Ping(vec![]),
                    &service_status,
                )
                .await;
            }
            Event::Cancellation => {
                let _ignore_failed_send = ws_stream.close().await;
                break;
            }
        }
    }
    // before terminating the task, marking channel as inactive and closing
    service_status.stop_service();
    let _ignore_closing_result = ws_stream.close().await;
}

async fn reader_task(
    mut ws_stream: SplitStream<WebSocketStream>,
    max_idle_time: Duration,
    pending_messages: Arc<Mutex<PendingMessagesMap>>,
    incoming_tx: mpsc::Sender<ServerRequest>,
    outgoing_tx: mpsc::Sender<Vec<u8>>,
    service_status: ServiceStatus<ChatNetworkError>,
) {
    enum Event {
        WsEvent(Option<Result<tungstenite::Message, tungstenite::Error>>),
        IdleCheck,
    }
    loop {
        let last_event_ts = Instant::now();
        let data = match tokio::select! {
            ws_event = ws_stream.next() => Event::WsEvent(ws_event),
            _ = tokio::time::sleep_until(last_event_ts + max_idle_time) => Event::IdleCheck,
        } {
            Event::WsEvent(Some(Ok(tungstenite::Message::Binary(data)))) => data,
            Event::WsEvent(Some(Ok(tungstenite::Message::Close(_)))) => {
                // connection is about to be closed
                // not immediately terminating the task,
                // but marking our channel as closed
                service_status.stop_service();
                continue;
            }
            Event::WsEvent(Some(Ok(tungstenite::Message::Pong(_)))) => {
                continue;
            }
            Event::WsEvent(Some(Ok(unexpected_frame))) => {
                // unexpected frame received
                log::debug!("Unexpected frame received: [{:?}]", unexpected_frame);
                service_status.stop_service_with_error(ChatNetworkError::UnexpectedFrameReceived);
                continue;
            }
            Event::WsEvent(Some(Err(tungstenite::Error::ConnectionClosed))) => {
                // error, possibly connection closed
                break;
            }
            Event::WsEvent(Some(Err(err))) => {
                // error, possibly connection closed
                service_status.stop_service_with_error(ChatNetworkError::WebSocketError(err));
                continue;
            }
            Event::WsEvent(None) => {
                // stream is exhausted nothing else will happen, we can exit now
                break;
            }
            Event::IdleCheck => {
                if Instant::now() - last_event_ts > max_idle_time {
                    // channel is idle
                    service_status.stop_service_with_error(ChatNetworkError::ChannelIdle);
                    break;
                }
                continue;
            }
        };

        // binary data received
        match decode_and_validate(data.as_slice()) {
            Ok(ChatMessage::Request(req)) => {
                let delivery_result = incoming_tx
                    .send(ServerRequest::new(req, outgoing_tx.clone()))
                    .await;
                if delivery_result.is_err() {
                    service_status.stop_service_with_error(
                        ChatNetworkError::FailedToPassMessageToIncomingChannel,
                    );
                }
            }
            Ok(ChatMessage::Response(id, res)) => {
                let map = &mut pending_messages.lock().await;
                if let Some(sender) = map.remove(&id) {
                    // this doesn't have to be successful,
                    // e.g. request might have timed out
                    let _ignore_failed_send = sender.send(res);
                }
            }
            Err(e) => {
                service_status.stop_service_with_error(e);
            }
        }
    }
    // before terminating the task, marking channel as inactive
    service_status.stop_service();
}

async fn send_and_validate(
    ws_stream: &mut SplitSink<WebSocketStream, tungstenite::Message>,
    msg: tungstenite::Message,
    service_status: &ServiceStatus<ChatNetworkError>,
) {
    let result = send_and_flush(ws_stream, msg).await;
    if let Err(e) = result {
        service_status.stop_service_with_error(e);
    }
}

async fn send_and_flush(
    ws_stream: &mut SplitSink<WebSocketStream, tungstenite::Message>,
    msg: tungstenite::Message,
) -> Result<(), ChatNetworkError> {
    ws_stream
        .send(msg)
        .await
        .map_err(ChatNetworkError::FailedToSendWebSocket)?;
    ws_stream
        .flush()
        .await
        .map_err(ChatNetworkError::FailedToSendWebSocket)?;
    Ok(())
}

fn decode_and_validate(data: &[u8]) -> Result<ChatMessage, ChatNetworkError> {
    let msg = MessageProto::decode(data).map_err(|_| ChatNetworkError::IncomingDataInvalid)?;
    // we want to guarantee that the message is either request or response
    match (
        msg.r#type
            .map(|x| ChatMessageType::try_from(x).expect("can parse chat message type")),
        msg.request,
        msg.response,
    ) {
        (Some(ChatMessageType::Request), Some(req), None) => Ok(ChatMessage::Request(req)),
        (Some(ChatMessageType::Response), None, Some(res)) => Ok(ChatMessage::Response(
            RequestId::new(res.id.ok_or(ChatNetworkError::IncomingDataInvalid)?),
            res,
        )),
        _ => Err(ChatNetworkError::IncomingDataInvalid),
    }
}

fn message_to_vec(msg: ChatMessage) -> Vec<u8> {
    match msg {
        ChatMessage::Request(req) => {
            let proto = MessageProto {
                r#type: Some(ChatMessageType::Request.into()),
                request: Some(req),
                response: None,
            };
            proto.encode_to_vec()
        }
        ChatMessage::Response(_, res) => {
            let proto = MessageProto {
                r#type: Some(ChatMessageType::Response.into()),
                request: None,
                response: Some(res),
            };
            proto.encode_to_vec()
        }
    }
}

fn response_for_code(id: u64, code: http::status::StatusCode) -> ResponseProto {
    ResponseProto {
        id: Some(id),
        status: Some(code.as_u16().into()),
        message: Some(
            code.canonical_reason()
                .expect("has canonical reason")
                .to_string(),
        ),
        headers: vec![],
        body: None,
    }
}
