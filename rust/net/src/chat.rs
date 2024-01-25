//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::sync::Arc;
use std::time::Duration;

use ::http::uri::PathAndQuery;
use ::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::mpsc;

use crate::chat::http::ChatOverHttp2ServiceConnector;
use crate::chat::ws::{ChatOverWebSocketServiceConnector, ServerRequest};
use crate::env::constants::WEB_SOCKET_PATH;
use crate::env::{WS_KEEP_ALIVE_INTERVAL, WS_MAX_CONNECTION_TIME, WS_MAX_IDLE_TIME};
use crate::infra::connection_manager::{
    MultiRouteConnectionManager, SingleRouteThrottlingConnectionManager,
};
use crate::infra::errors::NetError;
use crate::infra::reconnect::{ServiceConnectorWithDecorator, ServiceWithReconnect};
use crate::infra::ws::{WebSocketClientConnector, WebSocketConfig};
use crate::infra::{
    ConnectionParams, HttpRequestDecorator, TcpSslTransportConnector, TransportConnector,
};
use crate::proto;
use crate::utils::basic_authorization;

pub mod chat_reconnect;
pub mod http;
pub mod ws;

pub type MessageProto = proto::chat_websocket::WebSocketMessage;
pub type RequestProto = proto::chat_websocket::WebSocketRequestMessage;
pub type ResponseProto = proto::chat_websocket::WebSocketResponseMessage;
pub type ChatMessageType = proto::chat_websocket::web_socket_message::Type;

const HTTP_ONLY_ENDPOINTS: [&str; 2] = ["/v1/accounts", "/v2/keys"];
const ROUTE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(1);
const TOTAL_CONNECTION_TIMEOUT: Duration = Duration::from_secs(3);

#[async_trait]
pub trait ChatService {
    /// Sends request and get a response from the Chat Service.
    ///
    /// This API can be represented using different transports (e.g. WebSockets
    /// or HTTP) capable of sending [Request] objects.
    async fn send(&self, msg: Request, timeout: Duration) -> Result<Response, NetError>;
}

#[derive(Clone, Debug)]
pub struct Request {
    pub method: ::http::Method,
    pub body: Option<Box<[u8]>>,
    pub headers: HeaderMap,
    pub path: PathAndQuery,
}

impl Request {
    pub(crate) fn into_parts(self) -> (PathAndQuery, ::http::request::Builder, Bytes) {
        let Request {
            method,
            body,
            headers,
            path,
        } = self;

        let mut builder = ::http::request::Request::builder().method(method);
        let headers_map = builder.headers_mut().expect("have headers");
        headers_map.extend(headers);

        (path, builder, body.map_or_else(Bytes::new, Bytes::from))
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub status: StatusCode,
    pub body: Option<Box<[u8]>>,
    pub headers: HeaderMap,
}

impl TryFrom<ResponseProto> for Response {
    type Error = NetError;

    fn try_from(response_proto: ResponseProto) -> Result<Self, Self::Error> {
        let status = response_proto
            .status()
            .try_into()
            .map_err(|_| NetError::IncomingDataInvalid)
            .and_then(|status_code| {
                StatusCode::from_u16(status_code).map_err(|_| NetError::IncomingDataInvalid)
            })?;
        let body = response_proto.body.map(|v| v.into_boxed_slice());
        let headers = response_proto.headers.into_iter().try_fold(
            HeaderMap::new(),
            |mut headers, header_string| {
                let (name, value) = header_string
                    .split_once(':')
                    .ok_or(NetError::IncomingDataInvalid)?;
                let header_name =
                    HeaderName::try_from(name).map_err(|_| NetError::IncomingDataInvalid)?;
                let header_value = HeaderValue::from_str(value.trim())
                    .map_err(|_| NetError::IncomingDataInvalid)?;
                headers.append(header_name, header_value);
                Ok::<HeaderMap, NetError>(headers)
            },
        )?;
        Ok(Response {
            status,
            body,
            headers,
        })
    }
}

pub struct Chat<AuthService, UnauthService> {
    auth_service: AuthorizedChatService<AuthService>,
    unauth_service: AnonymousChatService<UnauthService>,
}

impl<AuthService, UnauthService> Chat<AuthService, UnauthService>
where
    AuthService: ChatService + Send + Sync,
    UnauthService: ChatService + Send + Sync,
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
        &self,
        msg: Request,
        timeout: Duration,
    ) -> Result<Response, NetError> {
        self.auth_service.send(msg, timeout).await
    }

    pub async fn send_unauthenticated(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> Result<Response, NetError> {
        self.unauth_service.send(msg, timeout).await
    }

    pub fn into_dyn(
        self,
    ) -> Chat<Arc<dyn ChatService + Send + Sync>, Arc<dyn ChatService + Send + Sync>>
    where
        AuthService: 'static,
        UnauthService: 'static,
    {
        let Self {
            auth_service,
            unauth_service,
        } = self;
        Chat::new(auth_service.into_dyn(), unauth_service.into_dyn())
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

    async fn send_ws(&self, msg: Request, timeout: Duration) -> Result<Response, NetError> {
        let ws_result = self.ws_service.send(msg.clone(), timeout).await;
        match ws_result {
            Ok(r) => Ok(r),
            Err(NetError::NoServiceConnection) => self.send_http(msg, timeout).await,
            Err(e) => Err(e),
        }
    }

    async fn send_http(&self, msg: Request, timeout: Duration) -> Result<Response, NetError> {
        self.http_service.send(msg, timeout).await
    }
}

#[async_trait]
impl<WsService, HttpService> ChatService for ChatServiceImpl<WsService, HttpService>
where
    WsService: ChatService + Send + Sync,
    HttpService: ChatService + Send + Sync,
{
    async fn send(&self, msg: Request, timeout: Duration) -> Result<Response, NetError> {
        if is_http_only_request(&msg) {
            self.send_http(msg, timeout).await
        } else {
            self.send_ws(msg, timeout).await
        }
    }
}

fn is_http_only_request(req: &Request) -> bool {
    let path = req.path.path();
    HTTP_ONLY_ENDPOINTS
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

pub struct AnonymousChatService<T> {
    inner: T,
}

impl<T: ChatService + Send + Sync + 'static> AnonymousChatService<T> {
    fn into_dyn(self) -> AnonymousChatService<Arc<dyn ChatService + Send + Sync>> {
        AnonymousChatService {
            inner: Arc::new(self.inner),
        }
    }
}

#[async_trait]
impl<T> ChatService for AnonymousChatService<T>
where
    T: ChatService + Send + Sync,
{
    async fn send(&self, msg: Request, timeout: Duration) -> Result<Response, NetError> {
        self.inner.send(msg, timeout).await
    }
}

pub struct AuthorizedChatService<T> {
    inner: T,
}

impl<T: ChatService + Send + Sync + 'static> AuthorizedChatService<T> {
    fn into_dyn(self) -> AuthorizedChatService<Arc<dyn ChatService + Send + Sync>> {
        AuthorizedChatService {
            inner: Arc::new(self.inner),
        }
    }
}

#[async_trait]
impl<T> ChatService for AuthorizedChatService<T>
where
    T: ChatService + Send + Sync,
{
    async fn send(&self, msg: Request, timeout: Duration) -> Result<Response, NetError> {
        self.inner.send(msg, timeout).await
    }
}

#[async_trait]
impl ChatService for Arc<dyn ChatService + Send + Sync> {
    async fn send(&self, msg: Request, timeout: Duration) -> Result<Response, NetError> {
        self.as_ref().send(msg, timeout).await
    }
}

fn build_authorized_chat_service(
    connection_manager_http: &MultiRouteConnectionManager,
    connection_manager_ws: &MultiRouteConnectionManager,
    service_connector_http: &ChatOverHttp2ServiceConnector<impl TransportConnector + 'static>,
    service_connector_ws: &ChatOverWebSocketServiceConnector<impl TransportConnector + 'static>,
    username: String,
    password: String,
) -> AuthorizedChatService<impl ChatService> {
    let header_auth_decorator =
        HttpRequestDecorator::HeaderAuth(basic_authorization(&username, &password));
    // http authorized
    let chat_over_h2_auth = ServiceWithReconnect::new(
        ServiceConnectorWithDecorator::new(
            service_connector_http.clone(),
            header_auth_decorator.clone(),
        ),
        connection_manager_http.clone(),
        TOTAL_CONNECTION_TIMEOUT,
    );

    // ws authorized
    let chat_over_ws_auth = ServiceWithReconnect::new(
        ServiceConnectorWithDecorator::new(
            service_connector_ws.clone(),
            header_auth_decorator.clone(),
        ),
        connection_manager_ws.clone(),
        TOTAL_CONNECTION_TIMEOUT,
    );

    AuthorizedChatService {
        inner: ChatServiceImpl::new(chat_over_ws_auth, chat_over_h2_auth),
    }
}

fn build_anonymous_chat_service(
    connection_manager_http: &MultiRouteConnectionManager,
    connection_manager_ws: &MultiRouteConnectionManager,
    service_connector_http: &ChatOverHttp2ServiceConnector<impl TransportConnector + 'static>,
    service_connector_ws: &ChatOverWebSocketServiceConnector<impl TransportConnector + 'static>,
) -> AnonymousChatService<impl ChatService> {
    // http anonymous
    let chat_over_h2_auth = ServiceWithReconnect::new(
        service_connector_http.clone(),
        connection_manager_http.clone(),
        TOTAL_CONNECTION_TIMEOUT,
    );

    // ws anonymous
    let chat_over_ws_auth = ServiceWithReconnect::new(
        service_connector_ws.clone(),
        connection_manager_ws.clone(),
        TOTAL_CONNECTION_TIMEOUT,
    );

    AnonymousChatService {
        inner: ChatServiceImpl::new(chat_over_ws_auth, chat_over_h2_auth),
    }
}

pub fn chat_service<T: TransportConnector + 'static>(
    username: String,
    password: String,
    incoming_tx: mpsc::Sender<ServerRequest<T::Stream>>,
    transport_connector: T,
    connection_params_list: Vec<ConnectionParams>,
) -> Chat<impl ChatService, impl ChatService> {
    let cfg = WebSocketConfig {
        ws_config: tungstenite::protocol::WebSocketConfig::default(),
        endpoint: PathAndQuery::from_static(WEB_SOCKET_PATH),
        max_connection_time: WS_MAX_CONNECTION_TIME,
        keep_alive_interval: WS_KEEP_ALIVE_INTERVAL,
        max_idle_time: WS_MAX_IDLE_TIME,
    };

    let service_connector_ws = ChatOverWebSocketServiceConnector::new(
        WebSocketClientConnector::new(transport_connector, cfg),
        incoming_tx,
    );
    let service_connector_http = ChatOverHttp2ServiceConnector::new(TcpSslTransportConnector);

    let connection_manager_http = multi_route_manager(&connection_params_list);
    let connection_manager_ws = multi_route_manager(&connection_params_list);

    Chat::new(
        build_authorized_chat_service(
            &connection_manager_http,
            &connection_manager_ws,
            &service_connector_http,
            &service_connector_ws,
            username,
            password,
        ),
        build_anonymous_chat_service(
            &connection_manager_http,
            &connection_manager_ws,
            &service_connector_http,
            &service_connector_ws,
        ),
    )
}

fn multi_route_manager(routes: &[ConnectionParams]) -> MultiRouteConnectionManager {
    let single_route_managers = routes
        .iter()
        .map(|cp| SingleRouteThrottlingConnectionManager::new(cp.clone(), ROUTE_CONNECTION_TIMEOUT))
        .collect();
    MultiRouteConnectionManager::new(single_route_managers, TOTAL_CONNECTION_TIMEOUT)
}

#[cfg(test)]
pub(crate) mod test {
    use crate::chat::{Response, ResponseProto};
    use crate::infra::errors::NetError;
    use assert_matches::assert_matches;
    use http::{HeaderName, HeaderValue};

    pub(crate) mod shared {
        use std::fmt::Debug;
        use std::time::Duration;

        use async_trait::async_trait;
        use http::Method;

        use crate::chat::{ChatService, Request, Response};
        use crate::infra::certs::RootCertificates;
        use crate::infra::connection_manager::SingleRouteThrottlingConnectionManager;
        use crate::infra::dns::DnsResolver;
        use crate::infra::errors::{LogSafeDisplay, NetError};
        use crate::infra::reconnect::{ServiceConnector, ServiceState};
        use crate::infra::test::shared::{NoReconnectService, TIMEOUT_DURATION};
        use crate::infra::ConnectionParams;

        #[async_trait]
        impl<C> ChatService for NoReconnectService<C>
        where
            C: ServiceConnector + Send + Sync + 'static,
            C::Service: ChatService + Clone + Send + Sync + 'static,
            C::Channel: Send + Sync,
            C::Error: Send + Sync + Debug + LogSafeDisplay,
        {
            async fn send(&self, msg: Request, timeout: Duration) -> Result<Response, NetError> {
                match &*self.inner {
                    ServiceState::Active(service, status) if !status.is_stopped() => {
                        service.clone().send(msg, timeout).await
                    }
                    _ => Err(NetError::NoServiceConnection),
                }
            }
        }

        pub fn test_request(method: Method, endpoint: &str) -> Request {
            Request {
                method,
                body: None,
                headers: Default::default(),
                path: endpoint.parse().expect("is valid"),
            }
        }

        pub fn connection_manager() -> SingleRouteThrottlingConnectionManager {
            let connection_params = ConnectionParams::new(
                "test.signal.org",
                "test.signal.org",
                443,
                Default::default(),
                RootCertificates::Signal,
                DnsResolver::default().into(),
            );
            SingleRouteThrottlingConnectionManager::new(connection_params, TIMEOUT_DURATION)
        }
    }

    #[test]
    fn proto_into_response_works_with_valid_data() {
        let expected_body = b"content";
        let expected_status = 200u16;
        let expected_host_value = "char.signal.org";
        let proto = ResponseProto {
            status: Some(expected_status.into()),
            headers: vec![format!("HOST: {}", expected_host_value)],
            body: Some(expected_body.to_vec()),
            message: None,
            id: None,
        };
        let response: Response = proto.try_into().unwrap();
        assert_eq!(expected_status, response.status.as_u16());
        assert_eq!(*expected_body, *response.body.unwrap());
        assert_eq!(
            expected_host_value,
            response
                .headers
                .get(http::header::HOST)
                .unwrap()
                .to_str()
                .unwrap()
        );
    }

    #[test]
    fn proto_into_response_works_with_valid_data_and_no_body() {
        let expected_status = 200u16;
        let expected_host_value = "char.signal.org";
        let proto = ResponseProto {
            status: Some(expected_status.into()),
            headers: vec![format!("HOST: {}", expected_host_value)],
            body: None,
            message: None,
            id: None,
        };
        let response: Response = proto.try_into().unwrap();
        assert_eq!(expected_status, response.status.as_u16());
        assert_eq!(None, response.body);
        assert_eq!(
            expected_host_value,
            response
                .headers
                .get(http::header::HOST)
                .unwrap()
                .to_str()
                .unwrap()
        );
    }

    #[test]
    fn proto_into_response_works_and_headers_parsed_correctly() {
        let proto = ResponseProto {
            status: Some(200),
            headers: vec![
                format!("{}: {}", http::header::FORWARDED.as_str(), "1.1.1.1"),
                format!("{}: {}", http::header::FORWARDED.as_str(), "2.2.2.2"),
                format!("{}: {}", http::header::HOST.as_str(), " chat.signal.org "),
                format!("{}: {}", http::header::USER_AGENT, ""),
            ],
            body: None,
            message: None,
            id: None,
        };
        let response: Response = proto.try_into().unwrap();

        fn values_to_vec(
            headers: &http::HeaderMap<HeaderValue>,
            header_name: HeaderName,
        ) -> Vec<&str> {
            headers
                .get_all(header_name)
                .into_iter()
                .map(|h| h.to_str().unwrap())
                .collect()
        }
        assert_eq!(
            vec![""],
            values_to_vec(&response.headers, http::header::USER_AGENT)
        );
        assert_eq!(
            vec!["chat.signal.org"],
            values_to_vec(&response.headers, http::header::HOST)
        );
        assert_eq!(
            vec!["1.1.1.1", "2.2.2.2"],
            values_to_vec(&response.headers, http::header::FORWARDED)
        );
    }

    #[test]
    fn proto_into_response_fails_for_invalid_data() {
        // status out of range of u16
        validate_invalid_data(Some(1 << 20), None, vec![]);
        // status in range, but value is invalid
        validate_invalid_data(Some(9999), None, vec![]);
        // status field is missing from the proto
        validate_invalid_data(None, None, vec![]);
        // header has an invalid value
        validate_invalid_data(Some(200), None, vec!["invalid header".to_string()]);
        validate_invalid_data(Some(200), None, vec!["invalid name: value".to_string()]);
        validate_invalid_data(Some(200), None, vec!["invalid_name : value".to_string()]);
        validate_invalid_data(Some(200), None, vec![" invalid_name: value".to_string()]);
    }

    fn validate_invalid_data(status: Option<u32>, body: Option<Vec<u8>>, headers: Vec<String>) {
        let proto = ResponseProto {
            status,
            headers,
            body,
            message: None,
            id: None,
        };
        let response: Result<Response, NetError> = proto.try_into();
        assert_matches!(response, Err(NetError::IncomingDataInvalid));
    }
}
