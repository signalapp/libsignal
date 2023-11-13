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
use http::header::ToStrError;
use prost::Message;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::{timeout_at, Instant};
use tokio_tungstenite::WebSocketStream;
use tungstenite::protocol::WebSocketConfig;

use crate::chat::errors::ChatNetworkError;
use crate::chat::{
    ChatMessageType, ChatService, MessageProto, Request, RequestProto, ResponseProto,
};
use crate::env::constants::WEB_SOCKET_PATH;
use crate::infra::reconnect::{ServiceConnector, ServiceStatus};
use crate::infra::ws::connect_websocket;
use crate::infra::{AsyncDuplexStream, ConnectionParams, TransportConnector};
use crate::proto::chat_websocket::web_socket_message::Type;
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
    pub request_proto: RequestProto,
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

#[derive(Default)]
struct PendingMessagesMap {
    pending: HashMap<RequestId, oneshot::Sender<ResponseProto>>,
    next_id: u64,
}

impl PendingMessagesMap {
    fn insert(&mut self, responder: oneshot::Sender<ResponseProto>) -> RequestId {
        let id = RequestId::new(self.next_id);
        let prev = self.pending.insert(id, responder);
        assert!(
            prev.is_none(),
            "IDs are picked uniquely and shouldn't wrap around in a reasonable amount of time"
        );
        self.next_id += 1;
        id
    }

    fn remove(&mut self, id: &RequestId) -> Option<oneshot::Sender<ResponseProto>> {
        self.pending.remove(id)
    }
}

#[derive(Clone)]
pub struct ChatOverWebSocketServiceConnector<C> {
    config: ChatOverWebsocketConfig,
    incoming_tx: mpsc::Sender<ServerRequest>,
    transport_connector: C,
}

impl<C> ChatOverWebSocketServiceConnector<C> {
    pub fn new(
        config: ChatOverWebsocketConfig,
        incoming_tx: mpsc::Sender<ServerRequest>,
        transport_connector: C,
    ) -> Self {
        Self {
            config,
            incoming_tx,
            transport_connector,
        }
    }
}

#[async_trait]
impl<C: TransportConnector> ServiceConnector for ChatOverWebSocketServiceConnector<C> {
    type Service = ChatOverWebSocket;
    type Channel = WebSocketStream<C::Stream>;
    type Error = ChatNetworkError;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::Error> {
        let connect_future = connect_websocket(
            connection_params,
            self.config.endpoint.clone(),
            self.config.ws_config,
            &self.transport_connector,
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
        &self,
        msg: Request,
        timeout: Duration,
    ) -> Result<ResponseProto, ChatNetworkError> {
        // checking if channel has been closed
        if self.service_status.is_stopped() {
            return Err(ChatNetworkError::ChannelClosed);
        }

        let (response_tx, response_rx) = oneshot::channel::<ResponseProto>();

        // defining a scope here to release the lock ASAP
        let id = {
            let map = &mut self.pending_messages.lock().await;
            map.insert(response_tx)
        };

        let msg = request_to_websocket_proto(msg, id)?;

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
    mut ws_stream: SplitSink<WebSocketStream<impl AsyncDuplexStream>, tungstenite::Message>,
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
                log::debug!("sending PING");
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
    mut ws_stream: SplitStream<WebSocketStream<impl AsyncDuplexStream>>,
    max_idle_time: Duration,
    pending_messages: Arc<Mutex<PendingMessagesMap>>,
    incoming_tx: mpsc::Sender<ServerRequest>,
    outgoing_tx: mpsc::Sender<Vec<u8>>,
    service_status: ServiceStatus<ChatNetworkError>,
) {
    // This variable holds the timestamp of the latest network activity event.
    // When listening to incoming frames/events, we will explicitly refresh it when needed.
    let mut last_event_ts = Instant::now();
    loop {
        let ws_event = match timeout_at(last_event_ts + max_idle_time, ws_stream.next()).await {
            Ok(ws_event) => ws_event,
            Err(_) => {
                service_status.stop_service_with_error(ChatNetworkError::ChannelIdle);
                break;
            }
        };
        let data = match ws_event {
            Some(Ok(tungstenite::Message::Binary(data))) => {
                last_event_ts = Instant::now();
                data
            }
            Some(Ok(tungstenite::Message::Close(_))) => {
                // connection is about to be closed
                // not immediately terminating the task,
                // but marking our channel as closed
                log::debug!("Received `Close` frame, stopping the service");
                service_status.stop_service();
                continue;
            }
            Some(Ok(tungstenite::Message::Pong(_))) => {
                log::debug!("received PONG");
                last_event_ts = Instant::now();
                continue;
            }
            Some(Ok(unexpected_frame)) => {
                // unexpected frame received
                log::debug!("Unexpected frame received: [{:?}]", unexpected_frame);
                service_status.stop_service_with_error(ChatNetworkError::UnexpectedFrameReceived);
                continue;
            }
            Some(Err(tungstenite::Error::ConnectionClosed)) => {
                // error, possibly connection closed
                break;
            }
            Some(Err(err)) => {
                // error, possibly connection closed
                service_status.stop_service_with_error(ChatNetworkError::WebSocketError(err));
                continue;
            }
            None => {
                // stream is exhausted nothing else will happen, we can exit now
                break;
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
    ws_stream: &mut SplitSink<WebSocketStream<impl AsyncDuplexStream>, tungstenite::Message>,
    msg: tungstenite::Message,
    service_status: &ServiceStatus<ChatNetworkError>,
) {
    let result = send_and_flush(ws_stream, msg).await;
    if let Err(e) = result {
        service_status.stop_service_with_error(e);
    }
}

async fn send_and_flush(
    ws_stream: &mut SplitSink<WebSocketStream<impl AsyncDuplexStream>, tungstenite::Message>,
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

fn request_to_websocket_proto(
    msg: Request,
    id: RequestId,
) -> Result<MessageProto, ChatNetworkError> {
    let headers = msg
        .headers
        .iter()
        .map(|(name, value)| Ok(format!("{name}: {}", value.to_str()?)))
        .collect::<Result<_, _>>()
        .map_err(|_: ToStrError| ChatNetworkError::RequestHasInvalidHeader)?;

    Ok(MessageProto {
        r#type: Some(Type::Request.into()),
        request: Some(RequestProto {
            verb: Some(msg.method.to_string()),
            path: Some(msg.path.to_string()),
            body: msg.body.map(Into::into),
            headers,
            id: Some(id.id),
        }),
        response: None,
    })
}

#[cfg(test)]
mod test {
    use std::default::Default;
    use std::fmt::Debug;
    use std::future::Future;
    use std::sync::Arc;
    use std::time::Duration;

    use assert_matches::assert_matches;
    use futures_util::{SinkExt, StreamExt};
    use http::{Method, StatusCode};
    use prost::Message;
    use tokio::sync::mpsc::Receiver;
    use tokio::sync::{mpsc, Mutex};
    use tokio::time::Instant;
    use warp::{Filter, Reply};

    use crate::chat::errors::ChatNetworkError;
    use crate::chat::test::shared::{connection_manager, test_request};
    use crate::chat::ws::{
        decode_and_validate, request_to_websocket_proto, ChatMessage,
        ChatOverWebSocketServiceConnector, ChatOverWebsocketConfig, RequestId, ServerRequest,
    };
    use crate::chat::{ChatMessageType, ChatService, MessageProto, ResponseProto};
    use crate::infra::test::shared::{
        InMemoryWarpConnector, NoReconnectService, TestError, TIMEOUT_DURATION,
    };

    #[derive(Debug)]
    enum ServerExitStatus {
        Success,
        Failure,
    }

    impl<T, E> From<Result<T, E>> for ServerExitStatus {
        fn from(value: Result<T, E>) -> Self {
            match value {
                Ok(_) => ServerExitStatus::Success,
                Err(_) => ServerExitStatus::Failure,
            }
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ws_service_connects_and_sends_pings() {
        let (ws_server, _) = ws_warp_filter(move |websocket| async move {
            let (_, mut rx) = websocket.split();
            // just listening (but also automatically responding to PINGs)
            while (rx.next().await).is_some() {}
            ServerExitStatus::Failure
        });

        let ws_config = ChatOverWebsocketConfig::default();
        let time_to_wait = ws_config.max_idle_time * 2;
        let (ws_chat, _) = create_ws_chat_service(ws_config, ws_server).await;
        assert!(!ws_chat.service_status().unwrap().is_stopped());

        // sleeping for a period of time long enough to stop the service
        // in case of missing PONG responses
        tokio::time::sleep(time_to_wait).await;
        assert!(!ws_chat.service_status().unwrap().is_stopped());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ws_service_connects_and_closes_after_not_receiving_pongs() {
        let ws_config = ChatOverWebsocketConfig::default();
        let duration = ws_config.max_idle_time * 2;

        // creating a server that is not responding to `PING` messages
        let (ws_server, _) = ws_warp_filter(move |_| async move {
            tokio::time::sleep(duration).await;
            ServerExitStatus::Success
        });

        let (ws_chat, _) = create_ws_chat_service(ws_config, ws_server).await;
        assert!(!ws_chat.service_status().unwrap().is_stopped());

        // sleeping for a period of time long enough for the service to stop,
        // which is what should happen since the PONG messages are not sent back
        tokio::time::sleep(duration).await;
        assert!(ws_chat.service_status().unwrap().is_stopped());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ws_service_stops_on_close_frame_from_server() {
        let ws_config = ChatOverWebsocketConfig::default();
        let time_before_close = ws_config.max_idle_time / 3;
        let time_to_wait = ws_config.max_idle_time / 2;

        // creating a server that works for a while and then initiates closing
        // by sending `Close` frame
        let (ws_server, server_res_rx) = ws_warp_filter(move |websocket| async move {
            let (mut tx, mut rx) = websocket.split();
            tokio::spawn(async move { while (rx.next().await).is_some() {} });
            tokio::time::sleep(time_before_close).await;
            tx.send(warp::filters::ws::Message::close()).await.into()
        });

        let (ws_chat, _) = create_ws_chat_service(ws_config, ws_server).await;
        assert!(!ws_chat.service_status().unwrap().is_stopped());

        // sleeping for a period of time long enough to stop the service
        // in case of missing PONG responses
        tokio::time::sleep(time_to_wait).await;
        assert!(ws_chat.service_status().unwrap().is_stopped());
        // making sure server logic completed in the expected way
        validate_server_stopped_successfully(server_res_rx).await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ws_service_stops_on_unexpected_frame_from_server() {
        let ws_config = ChatOverWebsocketConfig::default();
        let time_before_close = ws_config.max_idle_time / 3;
        let time_to_wait = ws_config.max_idle_time / 2;

        // creating a server that works for a while and then
        // sends an unexpected frame to the chat service client
        let (ws_server, server_res_rx) = ws_warp_filter(move |websocket| async move {
            let (mut tx, mut rx) = websocket.split();
            tokio::spawn(async move { while (rx.next().await).is_some() {} });
            tokio::time::sleep(time_before_close).await;
            tx.send(warp::filters::ws::Message::text("unexpected"))
                .await
                .into()
        });

        let ws_config = ChatOverWebsocketConfig::default();
        let (ws_chat, _) = create_ws_chat_service(ws_config, ws_server).await;
        assert!(!ws_chat.service_status().unwrap().is_stopped());

        // sleeping for a period of time long enough to stop the service
        // in case of missing PONG responses
        tokio::time::sleep(time_to_wait).await;
        assert!(ws_chat.service_status().unwrap().is_stopped());
        // making sure server logic completed in the expected way
        validate_server_stopped_successfully(server_res_rx).await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ws_service_sends_request_receives_response() {
        // creating a server that responds to requests with 200
        let (ws_server, server_res_rx) = ws_warp_filter(move |websocket| async move {
            let (mut tx, mut rx) = websocket.split();
            while let Some(Ok(msg)) = rx.next().await {
                if !msg.is_binary() {
                    return ServerExitStatus::Failure;
                }
                let request = decode_and_validate(msg.as_bytes()).expect("chat message");
                match response_for_request(&request, StatusCode::OK) {
                    Ok(message_proto) => {
                        let send_result = tx
                            .send(warp::ws::Message::binary(message_proto.encode_to_vec()))
                            .await;
                        if send_result.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            ServerExitStatus::Failure
        });

        let ws_config = ChatOverWebsocketConfig::default();
        let (ws_chat, _) = create_ws_chat_service(ws_config, ws_server).await;

        let response = ws_chat
            .send(test_request(Method::GET, "/"), TIMEOUT_DURATION)
            .await;
        response.expect("response");
        validate_server_running(server_res_rx).await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ws_service_times_out_on_late_response_from_server() {
        // creating a server that responds to requests with 200
        let (ws_server, server_res_rx) = ws_warp_filter(move |websocket| async move {
            let (mut tx, mut rx) = websocket.split();
            while let Some(Ok(msg)) = rx.next().await {
                if !msg.is_binary() {
                    return ServerExitStatus::Failure;
                }
                let request = decode_and_validate(msg.as_bytes()).expect("chat message");
                match response_for_request(&request, StatusCode::OK) {
                    Ok(message_proto) => {
                        tokio::time::sleep(TIMEOUT_DURATION * 2).await;
                        let send_result = tx
                            .send(warp::ws::Message::binary(message_proto.encode_to_vec()))
                            .await;
                        if send_result.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            ServerExitStatus::Failure
        });

        let ws_config = ChatOverWebsocketConfig::default();
        let (ws_chat, _) = create_ws_chat_service(ws_config, ws_server).await;

        let response = ws_chat
            .send(test_request(Method::GET, "/"), TIMEOUT_DURATION)
            .await;
        assert_matches!(response, Err(ChatNetworkError::Timeout));
        validate_server_running(server_res_rx).await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ws_service_fails_request_if_stopped_before_reponse_received() {
        // creating a server that responds to requests with 200
        let (ws_server, server_res_rx) = ws_warp_filter(move |websocket| async move {
            let (mut tx, mut rx) = websocket.split();
            if let Some(Ok(_)) = rx.next().await {
                tx.send(warp::ws::Message::close()).await.into()
            } else {
                ServerExitStatus::Failure
            }
        });

        let ws_config = ChatOverWebsocketConfig::default();
        let (ws_chat, _) = create_ws_chat_service(ws_config, ws_server).await;

        let response = ws_chat
            .send(test_request(Method::GET, "/"), TIMEOUT_DURATION)
            .await;
        assert_matches!(response, Err(ChatNetworkError::ChannelClosed));
        validate_server_stopped_successfully(server_res_rx).await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ws_service_receives_requests_from_server() {
        // creating a server that works for a while and then
        // sends an unexpected frame to the chat service client
        let (ws_server, _) = ws_warp_filter(move |websocket| async move {
            let (mut tx, mut rx) = websocket.split();
            let request = test_request(Method::GET, "/");
            let _ = tx
                .send(warp::filters::ws::Message::binary(
                    request_to_websocket_proto(request, RequestId::new(100))
                        .expect("is valid")
                        .encode_to_vec(),
                ))
                .await;
            if (rx.next().await).is_some() {
                ServerExitStatus::Success
            } else {
                ServerExitStatus::Failure
            }
        });

        let ws_config = ChatOverWebsocketConfig::default();
        let (_, mut incoming_rx) = create_ws_chat_service(ws_config, ws_server).await;

        incoming_rx.recv().await.expect("server request");
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ws_service_correctly_handles_multiple_in_flight_requests() {
        // creating a server that responds to requests with 200 after some request processing time
        const REQUEST_PROCESSING_DURATION: Duration =
            Duration::from_millis(TIMEOUT_DURATION.as_millis() as u64 / 2);
        let start = Instant::now();
        let (ws_server, _) = ws_warp_filter(move |websocket| async move {
            let (tx, mut rx) = websocket.split();
            let shared_sender = Arc::new(Mutex::new(tx));
            while let Some(Ok(msg)) = rx.next().await {
                if !msg.is_binary() {
                    return ServerExitStatus::Failure;
                }
                let request = decode_and_validate(msg.as_bytes()).expect("chat message");
                let response_proto =
                    response_for_request(&request, StatusCode::OK).expect("response");
                let shared_sender = shared_sender.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(REQUEST_PROCESSING_DURATION).await;
                    let mut sender = shared_sender.lock().await;
                    let _ignore_result = (*sender)
                        .send(warp::ws::Message::binary(response_proto.encode_to_vec()))
                        .await;
                });
            }
            ServerExitStatus::Failure
        });

        let ws_config = ChatOverWebsocketConfig::default();
        let (ws_chat, _) = create_ws_chat_service(ws_config, ws_server).await;

        let req1 = test_request(Method::GET, "/");
        let response1_future = ws_chat.send(req1, TIMEOUT_DURATION);

        let req2 = test_request(Method::GET, "/");
        let response2_future = ws_chat.send(req2, TIMEOUT_DURATION);

        // Making sure that at this point the clock has not advanced from the initial instant.
        // This is a way to indirectly make sure that neither of the futures is yet completed.
        assert_eq!(start, Instant::now());

        let (response1, response2) = tokio::join!(response1_future, response2_future);
        response1.expect("request 1 completed successfully");
        response2.expect("request 2 completed successfully");

        // And now making sure that both requests were in fact processed asynchronously,
        // i.e. one was not blocked on the other.
        assert_eq!(start + REQUEST_PROCESSING_DURATION, Instant::now());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ws_service_stops_on_malformed_data_from_server() {
        // creating a server that responds to requests with 200
        let (ws_server, server_res_rx) = ws_warp_filter(move |websocket| async move {
            let (mut tx, mut rx) = websocket.split();
            if let Some(Ok(_)) = rx.next().await {
                tx.send(warp::ws::Message::binary(b"invalid data".to_vec()))
                    .await
                    .into()
            } else {
                ServerExitStatus::Failure
            }
        });

        let ws_config = ChatOverWebsocketConfig::default();
        let (ws_chat, _) = create_ws_chat_service(ws_config, ws_server).await;

        let response = ws_chat
            .send(test_request(Method::GET, "/"), TIMEOUT_DURATION)
            .await;
        assert_matches!(response, Err(ChatNetworkError::ChannelClosed));
        validate_server_stopped_successfully(server_res_rx).await;
    }

    async fn validate_server_stopped_successfully(mut server_res_rx: Receiver<ServerExitStatus>) {
        assert_matches!(
            tokio::time::timeout(Duration::from_millis(100), server_res_rx.recv()).await,
            Ok(Some(ServerExitStatus::Success))
        );
    }

    async fn validate_server_running(mut server_res_rx: Receiver<ServerExitStatus>) {
        assert_matches!(
            tokio::time::timeout(Duration::from_millis(100), server_res_rx.recv()).await,
            Err(_)
        );
    }

    fn response_for_request(
        chat_message: &ChatMessage,
        status: StatusCode,
    ) -> Result<MessageProto, TestError> {
        let req = match chat_message {
            ChatMessage::Request(req) => req,
            ChatMessage::Response(_, _) => {
                return Err(TestError::Unexpected("message must be a request"))
            }
        };
        let id = req
            .id
            .ok_or(TestError::Unexpected("request must have an ID"))?;
        let response = ResponseProto {
            id: Some(id),
            status: Some(status.as_u16().into()),
            message: status.canonical_reason().map(|s| s.to_string()),
            headers: vec![],
            body: None,
        };
        Ok(MessageProto {
            r#type: Some(ChatMessageType::Response.into()),
            request: None,
            response: Some(response),
        })
    }

    async fn create_ws_chat_service<F>(
        ws_config: ChatOverWebsocketConfig,
        ws_server: F,
    ) -> (
        NoReconnectService<ChatOverWebSocketServiceConnector<InMemoryWarpConnector<F>>>,
        Receiver<ServerRequest>,
    )
    where
        F: Filter + Clone + Send + Sync + 'static,
        F::Extract: Reply,
    {
        let (incoming_tx, incoming_rx) = mpsc::channel::<ServerRequest>(512);
        let ws_connector = ChatOverWebSocketServiceConnector::new(
            ws_config,
            incoming_tx,
            InMemoryWarpConnector::new(ws_server),
        );
        let ws_chat = NoReconnectService::start(ws_connector, connection_manager()).await;
        (ws_chat, incoming_rx)
    }

    fn ws_warp_filter<F, T>(
        on_ws_upgrade_callback: F,
    ) -> (
        impl Filter<Extract = impl Reply> + Clone + Send + Sync + 'static,
        Receiver<ServerExitStatus>,
    )
    where
        F: Fn(warp::ws::WebSocket) -> T + Clone + Send + Sync + 'static,
        T: Future<Output = ServerExitStatus> + Send + 'static,
    {
        let (server_res_tx, server_res_rx) = mpsc::channel::<ServerExitStatus>(1);
        let filter = warp::any().and(warp::ws()).map(move |ws: warp::ws::Ws| {
            let on_ws_upgrade_callback = on_ws_upgrade_callback.clone();
            let server_res_tx = server_res_tx.clone();
            ws.on_upgrade(move |s| async move {
                let exit_status = on_ws_upgrade_callback(s).await;
                server_res_tx
                    .send(exit_status)
                    .await
                    .expect("sent successfully");
            })
        });
        (filter, server_res_rx)
    }
}
