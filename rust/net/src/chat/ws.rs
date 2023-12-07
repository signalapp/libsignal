//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use derive_where::derive_where;
use http::header::ToStrError;
use http::status::StatusCode;
use prost::Message;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio_tungstenite::WebSocketStream;

use crate::chat::{
    ChatMessageType, ChatService, MessageProto, Request, RequestProto, ResponseProto,
};
use crate::infra::errors::NetError;
use crate::infra::reconnect::{ServiceConnector, ServiceStatus};
use crate::infra::ws::{
    NextOrClose, TextOrBinary, WebSocketClientConnector, WebSocketClientReader,
    WebSocketClientWriter,
};
use crate::infra::{AsyncDuplexStream, ConnectionParams, TransportConnector};
use crate::proto::chat_websocket::web_socket_message::Type;

#[derive(Debug, Default, Eq, Hash, PartialEq, Clone, Copy)]
struct RequestId {
    id: u64,
}

impl RequestId {
    const fn new(id: u64) -> Self {
        Self { id }
    }
}

enum ChatMessage {
    Request(RequestProto),
    Response(RequestId, ResponseProto),
}

#[derive(Debug)]
pub struct ResponseSender<S> {
    request_id: u64,
    writer: WebSocketClientWriter<S>,
}

impl<S: AsyncDuplexStream> ResponseSender<S> {
    pub async fn send_response(self, status_code: StatusCode) -> Result<(), NetError> {
        let response = response_for_code(self.request_id, status_code);
        self.writer.send(response.encode_to_vec()).await
    }
}

#[derive(Debug)]
pub struct ServerRequest<S> {
    pub request_proto: RequestProto,
    pub response_sender: ResponseSender<S>,
}

impl<S: AsyncDuplexStream> ServerRequest<S> {
    fn new(
        request_proto: RequestProto,
        writer: WebSocketClientWriter<S>,
    ) -> Result<Self, NetError> {
        let request_id = request_proto.id.ok_or(NetError::ServerRequestMissingId)?;
        Ok(Self {
            request_proto,
            response_sender: ResponseSender { request_id, writer },
        })
    }
}

#[derive(Debug, Default)]
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

#[derive_where(Clone)]
pub(crate) struct ChatOverWebSocketServiceConnector<T: TransportConnector> {
    ws_client_connector: WebSocketClientConnector<T>,
    incoming_tx: mpsc::Sender<ServerRequest<T::Stream>>,
}

impl<T: TransportConnector> ChatOverWebSocketServiceConnector<T> {
    pub fn new(
        ws_client_connector: WebSocketClientConnector<T>,
        incoming_tx: mpsc::Sender<ServerRequest<T::Stream>>,
    ) -> Self {
        Self {
            ws_client_connector,
            incoming_tx,
        }
    }
}

#[async_trait]
impl<T: TransportConnector> ServiceConnector for ChatOverWebSocketServiceConnector<T> {
    type Service = ChatOverWebSocket<T::Stream>;
    type Channel = WebSocketStream<T::Stream>;
    type Error = NetError;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::Error> {
        self.ws_client_connector
            .connect_channel(connection_params)
            .await
    }

    fn start_service(&self, channel: Self::Channel) -> (Self::Service, ServiceStatus<Self::Error>) {
        let (ws_client, service_status) = self.ws_client_connector.start_service(channel);
        let (ws_client_writer, ws_client_reader) = ws_client.split();
        let pending_messages: Arc<Mutex<PendingMessagesMap>> = Default::default();
        tokio::spawn(reader_task(
            ws_client_reader,
            ws_client_writer.clone(),
            self.incoming_tx.clone(),
            pending_messages.clone(),
            service_status.clone(),
        ));
        (
            ChatOverWebSocket {
                ws_client_writer,
                service_status: service_status.clone(),
                pending_messages,
            },
            service_status,
        )
    }
}

async fn reader_task<S: AsyncDuplexStream + 'static>(
    mut ws_client_reader: WebSocketClientReader<S>,
    ws_client_writer: WebSocketClientWriter<S>,
    incoming_tx: mpsc::Sender<ServerRequest<S>>,
    pending_messages: Arc<Mutex<PendingMessagesMap>>,
    service_status: ServiceStatus<NetError>,
) {
    // This variable holds the timestamp of the latest network activity event.
    // When listening to incoming frames/events, we will explicitly refresh it when needed.
    loop {
        let data = match ws_client_reader.next().await {
            Ok(NextOrClose::Next(TextOrBinary::Binary(data))) => data,
            Ok(NextOrClose::Next(TextOrBinary::Text(_))) => {
                log::info!("Text frame received on chat websocket");
                service_status.stop_service_with_error(NetError::UnexpectedFrameReceived);
                break;
            }
            Ok(NextOrClose::Close(_)) => {
                service_status.stop_service_with_error(NetError::ChannelClosed);
                break;
            }
            Err(e) => {
                service_status.stop_service_with_error(e);
                break;
            }
        };

        // binary data received
        match decode_and_validate(data.as_slice()) {
            Ok(ChatMessage::Request(req)) => {
                let server_request = match ServerRequest::new(req, ws_client_writer.clone()) {
                    Ok(server_request) => server_request,
                    Err(e) => {
                        service_status.stop_service_with_error(e);
                        break;
                    }
                };
                let delivery_result = incoming_tx.send(server_request).await;
                if delivery_result.is_err() {
                    service_status
                        .stop_service_with_error(NetError::FailedToPassMessageToIncomingChannel);
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

#[derive_where(Clone)]
#[derive(Debug)]
pub struct ChatOverWebSocket<S> {
    ws_client_writer: WebSocketClientWriter<S>,
    service_status: ServiceStatus<NetError>,
    pending_messages: Arc<Mutex<PendingMessagesMap>>,
}

#[async_trait]
impl<S> ChatService for ChatOverWebSocket<S>
where
    S: AsyncDuplexStream,
{
    async fn send(&self, msg: Request, timeout: Duration) -> Result<ResponseProto, NetError> {
        // checking if channel has been closed
        if self.service_status.is_stopped() {
            return Err(NetError::ChannelClosed);
        }

        let (response_tx, response_rx) = oneshot::channel::<ResponseProto>();

        // defining a scope here to release the lock ASAP
        let id = {
            let map = &mut self.pending_messages.lock().await;
            map.insert(response_tx)
        };

        let msg = request_to_websocket_proto(msg, id)?;

        self.ws_client_writer.send(msg.encode_to_vec()).await?;

        let res = tokio::select! {
            result = response_rx => Ok(result.expect("sender is not dropped before receiver")),
            _ = tokio::time::sleep(timeout) => Err(NetError::Timeout),
            _ = self.service_status.stopped() => Err(NetError::ChannelClosed)
        };
        if res.is_err() {
            // in case of an error we need to clean up the listener from the `pending_messages` map
            let map = &mut self.pending_messages.lock().await;
            map.remove(&id);
        }
        res
    }
}

fn decode_and_validate(data: &[u8]) -> Result<ChatMessage, NetError> {
    let msg = MessageProto::decode(data).map_err(|_| NetError::IncomingDataInvalid)?;
    // we want to guarantee that the message is either request or response
    match (
        msg.r#type
            .map(|x| ChatMessageType::try_from(x).expect("can parse chat message type")),
        msg.request,
        msg.response,
    ) {
        (Some(ChatMessageType::Request), Some(req), None) => Ok(ChatMessage::Request(req)),
        (Some(ChatMessageType::Response), None, Some(res)) => Ok(ChatMessage::Response(
            RequestId::new(res.id.ok_or(NetError::IncomingDataInvalid)?),
            res,
        )),
        _ => Err(NetError::IncomingDataInvalid),
    }
}

fn response_for_code(id: u64, code: StatusCode) -> MessageProto {
    MessageProto {
        r#type: Some(Type::Response.into()),
        response: Some(ResponseProto {
            id: Some(id),
            status: Some(code.as_u16().into()),
            message: Some(
                code.canonical_reason()
                    .expect("has canonical reason")
                    .to_string(),
            ),
            headers: vec![],
            body: None,
        }),
        request: None,
    }
}

fn request_to_websocket_proto(msg: Request, id: RequestId) -> Result<MessageProto, NetError> {
    let headers = msg
        .headers
        .iter()
        .map(|(name, value)| Ok(format!("{name}: {}", value.to_str()?)))
        .collect::<Result<_, _>>()
        .map_err(|_: ToStrError| NetError::RequestHasInvalidHeader)?;

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
    use std::fmt::Debug;
    use std::future::Future;
    use std::sync::Arc;
    use std::time::Duration;

    use assert_matches::assert_matches;
    use futures_util::{SinkExt, StreamExt};
    use http::uri::PathAndQuery;
    use http::{Method, StatusCode};
    use prost::Message;
    use tokio::io::DuplexStream;
    use tokio::sync::mpsc::Receiver;
    use tokio::sync::{mpsc, Mutex};
    use tokio::time::Instant;
    use warp::{Filter, Reply};

    use crate::chat::test::shared::{connection_manager, test_request};
    use crate::chat::ws::{
        decode_and_validate, request_to_websocket_proto, ChatMessage,
        ChatOverWebSocketServiceConnector, RequestId, ServerRequest,
    };
    use crate::chat::{ChatMessageType, ChatService, MessageProto, ResponseProto};
    use crate::infra::errors::NetError;
    use crate::infra::test::shared::{
        InMemoryWarpConnector, NoReconnectService, TestError, TIMEOUT_DURATION,
    };
    use crate::infra::ws::{WebSocketClientConnector, WebSocketConfig};
    use crate::proto::chat_websocket::WebSocketMessage;

    fn test_ws_config() -> WebSocketConfig {
        WebSocketConfig {
            ws_config: tungstenite::protocol::WebSocketConfig::default(),
            endpoint: PathAndQuery::from_static("/test"),
            max_connection_time: Duration::from_secs(1),
            keep_alive_interval: Duration::from_secs(5),
            max_idle_time: Duration::from_secs(15),
        }
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ws_service_connects_and_sends_pings() {
        let (ws_server, _) = ws_warp_filter(move |websocket| async move {
            let (_, mut rx) = websocket.split();
            // just listening (but also automatically responding to PINGs)
            loop {
                let _: warp::ws::Message = rx.next().await.expect("is some").expect("not an error");
            }
        });

        let ws_config = test_ws_config();
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
        let ws_config = test_ws_config();
        let duration = ws_config.max_idle_time * 2;

        // creating a server that is not responding to `PING` messages
        let (ws_server, _) = ws_warp_filter(move |_| async move {
            tokio::time::sleep(duration).await;
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
        let ws_config = test_ws_config();
        let time_before_close = ws_config.max_idle_time / 3;
        let time_to_wait = ws_config.max_idle_time / 2;

        // creating a server that works for a while and then initiates closing
        // by sending `Close` frame
        let (ws_server, server_res_rx) = ws_warp_filter(move |websocket| async move {
            let (mut tx, mut rx) = websocket.split();
            tokio::spawn(async move { while (rx.next().await).is_some() {} });
            tokio::time::sleep(time_before_close).await;
            tx.send(warp::filters::ws::Message::close())
                .await
                .expect("can send")
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
        let ws_config = test_ws_config();
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
                .expect("can send")
        });

        let ws_config = test_ws_config();
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
            loop {
                let msg = rx
                    .next()
                    .await
                    .expect("stream should not be closed")
                    .expect("should be Ok");
                assert!(msg.is_binary(), "not binary: {msg:?}");
                let request = decode_and_validate(msg.as_bytes()).expect("chat message");
                let message_proto =
                    response_for_request(&request, StatusCode::OK).expect("not an error");
                let send_result = tx
                    .send(warp::ws::Message::binary(message_proto.encode_to_vec()))
                    .await;
                assert_matches!(send_result, Ok(_));
            }
        });

        let ws_config = test_ws_config();
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
            loop {
                let msg = rx.next().await.expect("not closed").expect("not an error");
                assert!(msg.is_binary(), "not binary: {msg:?}");
                let request = decode_and_validate(msg.as_bytes()).expect("chat message");
                let message_proto =
                    response_for_request(&request, StatusCode::OK).expect("is valid request");
                tokio::time::sleep(TIMEOUT_DURATION * 2).await;
                tx.send(warp::ws::Message::binary(message_proto.encode_to_vec()))
                    .await
                    .expect("can send response")
            }
        });

        let ws_config = test_ws_config();
        let (ws_chat, _) = create_ws_chat_service(ws_config, ws_server).await;

        let response = ws_chat
            .send(test_request(Method::GET, "/"), TIMEOUT_DURATION)
            .await;
        assert_matches!(response, Err(NetError::Timeout));
        validate_server_running(server_res_rx).await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ws_service_fails_request_if_stopped_before_reponse_received() {
        // creating a server that responds to requests with 200
        let (ws_server, server_res_rx) = ws_warp_filter(move |websocket| async move {
            let (mut tx, mut rx) = websocket.split();
            let _: warp::ws::Message = rx.next().await.expect("not closed").expect("not an error");
            tx.send(warp::ws::Message::close()).await.expect("can send")
        });

        let ws_config = test_ws_config();
        let (ws_chat, _) = create_ws_chat_service(ws_config, ws_server).await;

        let response = ws_chat
            .send(test_request(Method::GET, "/"), TIMEOUT_DURATION)
            .await;
        assert_matches!(response, Err(NetError::ChannelClosed));
        validate_server_stopped_successfully(server_res_rx).await;
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn ws_service_receives_requests_from_server_and_sends_back_response() {
        // creating a server that sends a request to client and then waits for response
        let (ws_server, server_res_rx) = ws_warp_filter(move |websocket| async move {
            let (mut tx, mut rx) = websocket.split();
            let request = test_request(Method::GET, "/");

            const REQUEST_ID: RequestId = RequestId::new(100);
            let request_proto = request_to_websocket_proto(request, REQUEST_ID).expect("is valid");
            let expected_response = response_for_request(
                &ChatMessage::Request(request_proto.request.clone().expect("is request")),
                StatusCode::OK,
            )
            .expect("is valid");

            tx.send(warp::filters::ws::Message::binary(
                request_proto.encode_to_vec(),
            ))
            .await
            .expect("can send");

            let response_from_client = WebSocketMessage::decode(
                rx.next()
                    .await
                    .expect("not closed")
                    .expect("not an error")
                    .as_bytes(),
            )
            .expect("can decode");
            assert_eq!(response_from_client, expected_response);
        });

        let ws_config = test_ws_config();
        let (_, mut incoming_rx) = create_ws_chat_service(ws_config, ws_server).await;

        let ServerRequest {
            request_proto: _,
            response_sender,
        } = incoming_rx.recv().await.expect("server request");

        response_sender
            .send_response(StatusCode::OK)
            .await
            .expect("response sent to back server");
        validate_server_stopped_successfully(server_res_rx).await;
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
            loop {
                let msg = rx.next().await.expect("not closed").expect("not an error");
                assert!(msg.is_binary(), "not binary: {msg:?}");
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
        });

        let ws_config = test_ws_config();
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
            let _: warp::ws::Message = rx.next().await.expect("not closed").expect("not an error");
            tx.send(warp::ws::Message::binary(b"invalid data".to_vec()))
                .await
                .expect("can reply")
        });

        let ws_config = test_ws_config();
        let (ws_chat, _) = create_ws_chat_service(ws_config, ws_server).await;

        let response = ws_chat
            .send(test_request(Method::GET, "/"), TIMEOUT_DURATION)
            .await;
        assert_matches!(response, Err(NetError::ChannelClosed));
        validate_server_stopped_successfully(server_res_rx).await;
    }

    #[derive(Debug)]
    struct ServerExitError;

    async fn validate_server_stopped_successfully(
        mut server_res_rx: Receiver<Result<(), ServerExitError>>,
    ) {
        assert_matches!(
            tokio::time::timeout(Duration::from_millis(100), server_res_rx.recv()).await,
            Ok(Some(Ok(())))
        );
    }

    async fn validate_server_running(mut server_res_rx: Receiver<Result<(), ServerExitError>>) {
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
        ws_config: WebSocketConfig,
        ws_server: F,
    ) -> (
        NoReconnectService<ChatOverWebSocketServiceConnector<InMemoryWarpConnector<F>>>,
        Receiver<ServerRequest<DuplexStream>>,
    )
    where
        F: Filter + Clone + Send + Sync + 'static,
        F::Extract: Reply,
    {
        let (incoming_tx, incoming_rx) = mpsc::channel::<ServerRequest<DuplexStream>>(512);
        let ws_connector = ChatOverWebSocketServiceConnector::new(
            WebSocketClientConnector::new(InMemoryWarpConnector::new(ws_server), ws_config),
            incoming_tx,
        );
        let ws_chat = NoReconnectService::start(ws_connector, connection_manager()).await;
        (ws_chat, incoming_rx)
    }

    fn ws_warp_filter<F, T>(
        on_ws_upgrade_callback: F,
    ) -> (
        impl Filter<Extract = impl Reply> + Clone + Send + Sync + 'static,
        Receiver<Result<(), ServerExitError>>,
    )
    where
        F: Fn(warp::ws::WebSocket) -> T + Clone + Send + Sync + 'static,
        T: Future<Output = ()> + Send + 'static,
    {
        let (server_res_tx, server_res_rx) = mpsc::channel::<Result<(), ServerExitError>>(1);
        let filter = warp::any().and(warp::ws()).map(move |ws: warp::ws::Ws| {
            let on_ws_upgrade_callback = on_ws_upgrade_callback.clone();
            let server_res_tx = server_res_tx.clone();
            ws.on_upgrade(move |s| async move {
                // Invoke the callback. Turn panics into errors so that the callback can use
                // assert! and friends.
                let exit_status = tokio::task::spawn(on_ws_upgrade_callback(s))
                    .await
                    .map_err(|_panic| ServerExitError);
                server_res_tx
                    .send(exit_status)
                    .await
                    .expect("sent successfully");
            })
        });
        (filter, server_res_rx)
    }
}
