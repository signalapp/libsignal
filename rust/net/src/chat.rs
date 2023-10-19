//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::chat::errors::ChatNetworkError;
use crate::chat::http::ChatOverHttp2ServiceConnector;
use crate::chat::ws::{ChatOverWebSocketServiceConnector, ChatOverWebsocketConfig, ServerRequest};
use crate::infra::connection_manager::{
    MultiRouteConnectionManager, SingleRouteThrottlingConnectionManager,
};
use crate::infra::reconnect::ServiceWithReconnect;
use crate::infra::{ConnectionParams, HttpRequestDecorator};
use crate::proto;
use crate::utils::basic_authorization;
use ::http::{HeaderName, HeaderValue};
use async_trait::async_trait;
use bytes::Bytes;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::mpsc;

pub mod chat_reconnect;
pub mod errors;
pub mod http;
pub mod ws;

pub type MessageProto = proto::chat_websocket::WebSocketMessage;
pub type RequestProto = proto::chat_websocket::WebSocketRequestMessage;
pub type ResponseProto = proto::chat_websocket::WebSocketResponseMessage;
pub type ChatMessageType = proto::chat_websocket::web_socket_message::Type;

const HTTP_ONLY_ENDPOINTS: [&str; 2] = ["/v1/accounts", "/v2/keys"];

#[async_trait]
pub trait ChatService {
    /// Sends request and get a response from the Chat Service.
    ///
    /// This API can be represented using different transports (e.g. WebSockets or HTTP).
    /// Although this method takes in an argument of type [MessageProto], it is expected
    /// that this message is a request. The reason for chosing a more abstract type is that
    /// at some point in the pipeline, an instance of [MessageProto] will need to be created
    /// as it is what the server side expects on the wire. However, the [MessageProto] owns
    /// its content, so passing request by reference would not be possible without neccessarily
    /// cloning the request.
    async fn send(
        &mut self,
        msg: &MessageProto,
        timeout: Duration,
    ) -> Result<ResponseProto, ChatNetworkError>;
}

pub struct Chat<AuthService, UnauthService> {
    auth_service: AuthorizedChatService<AuthService>,
    unauth_service: AnonymousChatService<UnauthService>,
}

impl<AuthService, UnauthService> Chat<AuthService, UnauthService>
where
    AuthService: ChatService + Send,
    UnauthService: ChatService + Send,
{
    pub fn new(
        auth_service: AuthorizedChatService<AuthService>,
        unauth_service: AnonymousChatService<UnauthService>,
    ) -> Self {
        Self {
            auth_service,
            unauth_service,
        }
    }

    pub async fn send_authenticated(
        &mut self,
        msg: &MessageProto,
        timeout: Duration,
    ) -> Result<ResponseProto, ChatNetworkError> {
        self.auth_service.send(msg, timeout).await
    }

    pub async fn send_unauthenticated(
        &mut self,
        msg: &MessageProto,
        timeout: Duration,
    ) -> Result<ResponseProto, ChatNetworkError> {
        self.unauth_service.send(msg, timeout).await
    }
}

#[derive(Clone)]
struct ChatServiceImpl<WsService, HttpService> {
    ws_service: WsService,
    http_service: HttpService,
}

impl<WsService, HttpService> ChatServiceImpl<WsService, HttpService>
where
    WsService: ChatService,
    HttpService: ChatService,
{
    #[allow(dead_code)]
    pub fn new(ws_service: WsService, http_service: HttpService) -> Self {
        Self {
            ws_service,
            http_service,
        }
    }

    async fn send_ws(
        &mut self,
        msg: &MessageProto,
        timeout: Duration,
    ) -> Result<ResponseProto, ChatNetworkError> {
        let ws_result = self.ws_service.send(msg, timeout).await;
        match ws_result {
            Ok(r) => Ok(r),
            Err(ChatNetworkError::NoServiceConnection) => self.send_http(msg, timeout).await,
            Err(e) => Err(e),
        }
    }

    async fn send_http(
        &mut self,
        msg: &MessageProto,
        timeout: Duration,
    ) -> Result<ResponseProto, ChatNetworkError> {
        self.http_service.send(msg, timeout).await
    }
}

#[async_trait]
impl<WsService, HttpService> ChatService for ChatServiceImpl<WsService, HttpService>
where
    WsService: ChatService + Send,
    HttpService: ChatService + Send,
{
    async fn send(
        &mut self,
        msg: &MessageProto,
        timeout: Duration,
    ) -> Result<ResponseProto, ChatNetworkError> {
        let req = msg
            .request
            .as_ref()
            .ok_or(ChatNetworkError::UnexpectedMessageType)?;
        if is_http_only_request(req) {
            self.send_http(msg, timeout).await
        } else {
            self.send_ws(msg, timeout).await
        }
    }
}

fn is_http_only_request(req: &RequestProto) -> bool {
    req.path.as_ref().map_or(false, |path| {
        HTTP_ONLY_ENDPOINTS
            .iter()
            .any(|prefix| path.starts_with(prefix))
    })
}

pub(crate) fn proto_to_request(
    req: &RequestProto,
) -> Result<(String, ::http::request::Builder, Bytes), ChatNetworkError> {
    let (verb, path, headers, maybe_body) = match req {
        RequestProto {
            verb: Some(v),
            path: Some(p),
            ..
        } => Ok((v, p, &req.headers, &req.body)),
        _ => Err(ChatNetworkError::RequestMissingVerbOrPath),
    }?;

    let method = ::http::method::Method::from_str(verb.as_str())
        .map_err(|_| ChatNetworkError::UnknownVerbInRequest)?;

    let body = match maybe_body {
        Some(b) => Bytes::from(b.clone()),
        None => Bytes::new(),
    };

    let mut builder = ::http::request::Request::builder().method(method);

    let headers_map = builder.headers_mut().expect("have headers");
    for header_str in headers.iter() {
        if let Some((key, value)) = header_str.split_once(':') {
            headers_map.insert(
                HeaderName::from_str(key).expect("can parse header name"),
                HeaderValue::from_str(value).expect("can parse header value"),
            );
        }
    }

    Ok((path.to_string(), builder, body))
}

pub struct AnonymousChatService<T> {
    inner: T,
}

#[async_trait]
impl<T> ChatService for AnonymousChatService<T>
where
    T: ChatService + Send,
{
    async fn send(
        &mut self,
        msg: &MessageProto,
        timeout: Duration,
    ) -> Result<ResponseProto, ChatNetworkError> {
        self.inner.send(msg, timeout).await
    }
}

pub struct AuthorizedChatService<T> {
    inner: T,
}

#[async_trait]
impl<T> ChatService for AuthorizedChatService<T>
where
    T: ChatService + Send,
{
    async fn send(
        &mut self,
        msg: &MessageProto,
        timeout: Duration,
    ) -> Result<ResponseProto, ChatNetworkError> {
        self.inner.send(msg, timeout).await
    }
}

fn build_authorized_chat_service(
    connection_params_list: &[ConnectionParams],
    service_connector_http: &ChatOverHttp2ServiceConnector,
    service_connector_ws: &ChatOverWebSocketServiceConnector,
    username: String,
    password: String,
) -> AuthorizedChatService<impl ChatService> {
    let connection_params_list_auth: Vec<ConnectionParams> = connection_params_list
        .iter()
        .cloned()
        .map(|cp| {
            cp.with_decorator(HttpRequestDecorator::HeaderAuth(basic_authorization(
                &username, &password,
            )))
        })
        .collect();

    // http authorized
    let connection_manager_auth_http = multi_route_manager(&connection_params_list_auth);
    let chat_over_h2_auth =
        ServiceWithReconnect::start(service_connector_http.clone(), connection_manager_auth_http);

    // ws authorized
    let connection_manager_auth_ws = multi_route_manager(&connection_params_list_auth);
    let chat_over_ws_auth =
        ServiceWithReconnect::start(service_connector_ws.clone(), connection_manager_auth_ws);

    AuthorizedChatService {
        inner: ChatServiceImpl::new(chat_over_ws_auth, chat_over_h2_auth),
    }
}

fn build_anonymous_chat_service(
    connection_params_list: &[ConnectionParams],
    service_connector_http: &ChatOverHttp2ServiceConnector,
    service_connector_ws: &ChatOverWebSocketServiceConnector,
) -> AnonymousChatService<impl ChatService> {
    // http authorized
    let connection_manager_auth_http = multi_route_manager(connection_params_list);
    let chat_over_h2_auth =
        ServiceWithReconnect::start(service_connector_http.clone(), connection_manager_auth_http);

    // ws authorized
    let connection_manager_auth_ws = multi_route_manager(connection_params_list);
    let chat_over_ws_auth =
        ServiceWithReconnect::start(service_connector_ws.clone(), connection_manager_auth_ws);

    AnonymousChatService {
        inner: ChatServiceImpl::new(chat_over_ws_auth, chat_over_h2_auth),
    }
}

#[allow(dead_code)]
pub(crate) fn chat_service(
    username: String,
    password: String,
    incoming_tx: mpsc::Sender<ServerRequest>,
    connection_params_list: Vec<ConnectionParams>,
) -> Chat<impl ChatService, impl ChatService> {
    let service_connector_ws =
        ChatOverWebSocketServiceConnector::new(ChatOverWebsocketConfig::default(), incoming_tx);
    let service_connector_http = ChatOverHttp2ServiceConnector {};

    Chat::new(
        build_authorized_chat_service(
            &connection_params_list,
            &service_connector_http,
            &service_connector_ws,
            username,
            password,
        ),
        build_anonymous_chat_service(
            &connection_params_list,
            &service_connector_http,
            &service_connector_ws,
        ),
    )
}

fn multi_route_manager(routes: &[ConnectionParams]) -> MultiRouteConnectionManager {
    let single_route_managers = routes
        .iter()
        .map(|cp| SingleRouteThrottlingConnectionManager::new(cp.clone()))
        .collect();
    MultiRouteConnectionManager::new(single_route_managers)
}
