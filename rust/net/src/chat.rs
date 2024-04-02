//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::sync::Arc;
use std::time::Duration;

use ::http::uri::PathAndQuery;
use ::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use async_trait::async_trait;

use crate::chat::ws::{ChatOverWebSocketServiceConnector, ServerRequest};
use crate::infra::connection_manager::MultiRouteConnectionManager;
use crate::infra::reconnect::{ServiceConnectorWithDecorator, ServiceWithReconnect};
use crate::infra::ws::WebSocketClientConnector;
use crate::infra::{
    ConnectionInfo, EndpointConnection, HttpRequestDecorator, IpType, TransportConnector,
};
use crate::proto;
use crate::utils::basic_authorization;

pub mod chat_reconnect;
mod error;
pub use error::ChatServiceError;
pub mod ws;

pub type MessageProto = proto::chat_websocket::WebSocketMessage;
pub type RequestProto = proto::chat_websocket::WebSocketRequestMessage;
pub type ResponseProto = proto::chat_websocket::WebSocketResponseMessage;
pub type ChatMessageType = proto::chat_websocket::web_socket_message::Type;

const TOTAL_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

#[async_trait]
pub trait ChatService {
    /// Sends request and gets a response from the Chat Service.
    ///
    /// This API can be represented using different transports (e.g. WebSockets
    /// or HTTP) capable of sending [Request] objects.
    async fn send(&self, msg: Request, timeout: Duration) -> Result<Response, ChatServiceError>;

    /// Establish a connection without sending a request.
    async fn connect(&self) -> Result<(), ChatServiceError>;

    /// If the service is currently holding an open connection, closes that connection.
    ///
    /// Depending on the implementing logic, the connection may be re-established later
    /// with a call to [ChatService::send].
    async fn disconnect(&self);
}

#[async_trait]
pub trait ChatServiceWithDebugInfo: ChatService {
    /// Sends request and gets a response from the Chat Service along with the connection debug info.
    async fn send_and_debug(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> (Result<Response, ChatServiceError>, DebugInfo);

    /// Establish a connection without sending a request.
    async fn connect_and_debug(&self) -> Result<DebugInfo, ChatServiceError>;
}

pub trait RemoteAddressInfo {
    /// Provides information about the remote address the service is connected to
    fn connection_info(&self) -> ConnectionInfo;
}

#[derive(Debug)]
pub struct DebugInfo {
    /// Indicates if the connection was active at the time of the call.
    pub connection_reused: bool,
    /// Number of times a connection had to be established since the service was created.
    pub reconnect_count: u32,
    /// IP type of the connection that was used for the request.
    pub ip_type: IpType,
    /// Time it took to complete the request.
    pub duration: Duration,
    /// Connection information summary.
    pub connection_info: String,
}

#[derive(Clone, Debug)]
pub struct Request {
    pub method: ::http::Method,
    pub body: Option<Box<[u8]>>,
    pub headers: HeaderMap,
    pub path: PathAndQuery,
}

#[derive(Clone, Debug)]
pub struct Response {
    pub status: StatusCode,
    pub message: Option<String>,
    pub body: Option<Box<[u8]>>,
    pub headers: HeaderMap,
}

#[derive(Debug)]
pub struct ResponseProtoInvalidError;

impl TryFrom<ResponseProto> for Response {
    type Error = ResponseProtoInvalidError;

    fn try_from(response_proto: ResponseProto) -> Result<Self, Self::Error> {
        let status = response_proto
            .status()
            .try_into()
            .map_err(|_| ResponseProtoInvalidError)
            .and_then(|status_code| {
                StatusCode::from_u16(status_code).map_err(|_| ResponseProtoInvalidError)
            })?;
        let message = response_proto.message;
        let body = response_proto.body.map(|v| v.into_boxed_slice());
        let headers = response_proto.headers.into_iter().try_fold(
            HeaderMap::new(),
            |mut headers, header_string| {
                let (name, value) = header_string
                    .split_once(':')
                    .ok_or(ResponseProtoInvalidError)?;
                let header_name =
                    HeaderName::try_from(name).map_err(|_| ResponseProtoInvalidError)?;
                let header_value =
                    HeaderValue::from_str(value.trim()).map_err(|_| ResponseProtoInvalidError)?;
                headers.append(header_name, header_value);
                Ok(headers)
            },
        )?;
        Ok(Response {
            status,
            message,
            body,
            headers,
        })
    }
}

impl From<ResponseProtoInvalidError> for ChatServiceError {
    fn from(ResponseProtoInvalidError: ResponseProtoInvalidError) -> Self {
        Self::IncomingDataInvalid
    }
}

pub struct Chat<AuthService, UnauthService> {
    auth_service: AuthorizedChatService<AuthService>,
    unauth_service: AnonymousChatService<UnauthService>,
}

impl<AuthService, UnauthService> Chat<AuthService, UnauthService>
where
    AuthService: ChatServiceWithDebugInfo + Send + Sync,
    UnauthService: ChatServiceWithDebugInfo + Send + Sync,
{
    pub async fn send_authenticated(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> Result<Response, ChatServiceError> {
        self.auth_service.send(msg, timeout).await
    }

    pub async fn send_unauthenticated(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> Result<Response, ChatServiceError> {
        self.unauth_service.send(msg, timeout).await
    }

    pub async fn send_authenticated_and_debug(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> (Result<Response, ChatServiceError>, DebugInfo) {
        self.auth_service.send_and_debug(msg, timeout).await
    }

    pub async fn send_unauthenticated_and_debug(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> (Result<Response, ChatServiceError>, DebugInfo) {
        self.unauth_service.send_and_debug(msg, timeout).await
    }

    pub async fn connect_authenticated(&self) -> Result<DebugInfo, ChatServiceError> {
        self.auth_service.connect_and_debug().await
    }

    pub async fn connect_unauthenticated(&self) -> Result<DebugInfo, ChatServiceError> {
        self.unauth_service.connect_and_debug().await
    }

    pub async fn disconnect(&self) {
        self.unauth_service.disconnect().await;
        self.auth_service.disconnect().await;
    }

    pub fn into_dyn(
        self,
    ) -> Chat<
        Arc<dyn ChatServiceWithDebugInfo + Send + Sync>,
        Arc<dyn ChatServiceWithDebugInfo + Send + Sync>,
    >
    where
        AuthService: 'static,
        UnauthService: 'static,
    {
        let Self {
            auth_service,
            unauth_service,
        } = self;
        {
            let auth_service = auth_service.into_dyn();
            let unauth_service = unauth_service.into_dyn();
            Chat {
                auth_service,
                unauth_service,
            }
        }
    }
}

struct AnonymousChatService<T> {
    inner: T,
}

impl<T: ChatServiceWithDebugInfo + Send + Sync + 'static> AnonymousChatService<T> {
    fn into_dyn(self) -> AnonymousChatService<Arc<dyn ChatServiceWithDebugInfo + Send + Sync>> {
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
    async fn send(&self, msg: Request, timeout: Duration) -> Result<Response, ChatServiceError> {
        self.inner.send(msg, timeout).await
    }

    async fn connect(&self) -> Result<(), ChatServiceError> {
        self.inner.connect().await
    }

    async fn disconnect(&self) {
        self.inner.disconnect().await
    }
}

#[async_trait]
impl<T> ChatServiceWithDebugInfo for AnonymousChatService<T>
where
    T: ChatServiceWithDebugInfo + Send + Sync,
{
    async fn send_and_debug(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> (Result<Response, ChatServiceError>, DebugInfo) {
        self.inner.send_and_debug(msg, timeout).await
    }

    async fn connect_and_debug(&self) -> Result<DebugInfo, ChatServiceError> {
        self.inner.connect_and_debug().await
    }
}

struct AuthorizedChatService<T> {
    inner: T,
}

impl<T: ChatServiceWithDebugInfo + Send + Sync + 'static> AuthorizedChatService<T> {
    fn into_dyn(self) -> AuthorizedChatService<Arc<dyn ChatServiceWithDebugInfo + Send + Sync>> {
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
    async fn send(&self, msg: Request, timeout: Duration) -> Result<Response, ChatServiceError> {
        self.inner.send(msg, timeout).await
    }

    async fn connect(&self) -> Result<(), ChatServiceError> {
        self.inner.connect().await
    }

    async fn disconnect(&self) {
        self.inner.disconnect().await
    }
}

#[async_trait]
impl ChatService for Arc<dyn ChatService + Send + Sync> {
    async fn send(&self, msg: Request, timeout: Duration) -> Result<Response, ChatServiceError> {
        self.as_ref().send(msg, timeout).await
    }

    async fn connect(&self) -> Result<(), ChatServiceError> {
        self.as_ref().connect().await
    }

    async fn disconnect(&self) {
        self.as_ref().disconnect().await
    }
}

#[async_trait]
impl<T> ChatServiceWithDebugInfo for AuthorizedChatService<T>
where
    T: ChatServiceWithDebugInfo + Send + Sync,
{
    async fn send_and_debug(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> (Result<Response, ChatServiceError>, DebugInfo) {
        self.inner.send_and_debug(msg, timeout).await
    }

    async fn connect_and_debug(&self) -> Result<DebugInfo, ChatServiceError> {
        self.inner.connect_and_debug().await
    }
}

/// Wraps a ChatService `T` to automatically call [`disconnect`][ChatService::disconnect] on Drop.
///
/// If dropped in a tokio context, the disconnect will happen asynchronously.
///
/// Deliberately does *not* implement Clone; this interface only makes sense as a way to impose a
/// single owner on an underlying cloneable ChatService.
struct AutoDisconnecting<T: ChatService + Clone + Send + Sync + 'static> {
    inner: T,
}

impl<T: ChatService + Clone + Send + Sync + 'static> Drop for AutoDisconnecting<T> {
    fn drop(&mut self) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let inner = self.inner.clone();
            handle.spawn(async move { inner.disconnect().await });
        } else {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .expect("can create ad-hoc runtime")
                .block_on(self.inner.disconnect())
        }
    }
}

#[async_trait]
impl<T> ChatService for AutoDisconnecting<T>
where
    T: ChatService + Clone + Send + Sync,
{
    async fn send(&self, msg: Request, timeout: Duration) -> Result<Response, ChatServiceError> {
        self.inner.send(msg, timeout).await
    }

    async fn connect(&self) -> Result<(), ChatServiceError> {
        self.inner.connect().await
    }

    async fn disconnect(&self) {
        self.inner.disconnect().await
    }
}

#[async_trait]
impl<T> ChatServiceWithDebugInfo for AutoDisconnecting<T>
where
    T: ChatServiceWithDebugInfo + Clone + Send + Sync,
{
    async fn send_and_debug(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> (Result<Response, ChatServiceError>, DebugInfo) {
        self.inner.send_and_debug(msg, timeout).await
    }

    async fn connect_and_debug(&self) -> Result<DebugInfo, ChatServiceError> {
        self.inner.connect_and_debug().await
    }
}

#[async_trait]
impl ChatService for Arc<dyn ChatServiceWithDebugInfo + Send + Sync> {
    async fn send(&self, msg: Request, timeout: Duration) -> Result<Response, ChatServiceError> {
        self.as_ref().send(msg, timeout).await
    }

    async fn connect(&self) -> Result<(), ChatServiceError> {
        self.as_ref().connect().await
    }

    async fn disconnect(&self) {
        self.as_ref().disconnect().await
    }
}

#[async_trait]
impl ChatServiceWithDebugInfo for Arc<dyn ChatServiceWithDebugInfo + Send + Sync> {
    async fn send_and_debug(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> (Result<Response, ChatServiceError>, DebugInfo) {
        self.as_ref().send_and_debug(msg, timeout).await
    }

    async fn connect_and_debug(&self) -> Result<DebugInfo, ChatServiceError> {
        self.as_ref().connect_and_debug().await
    }
}

fn build_authorized_chat_service(
    connection_manager_ws: &MultiRouteConnectionManager,
    service_connector_ws: &ChatOverWebSocketServiceConnector<impl TransportConnector + 'static>,
    username: String,
    password: String,
) -> AuthorizedChatService<impl ChatServiceWithDebugInfo> {
    let header_auth_decorator =
        HttpRequestDecorator::HeaderAuth(basic_authorization(&username, &password));

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
        inner: AutoDisconnecting {
            inner: chat_over_ws_auth,
        },
    }
}

fn build_anonymous_chat_service(
    connection_manager_ws: &MultiRouteConnectionManager,
    service_connector_ws: &ChatOverWebSocketServiceConnector<impl TransportConnector + 'static>,
) -> AnonymousChatService<impl ChatServiceWithDebugInfo> {
    // ws anonymous
    let chat_over_ws_anonymous = ServiceWithReconnect::new(
        service_connector_ws.clone(),
        connection_manager_ws.clone(),
        TOTAL_CONNECTION_TIMEOUT,
    );

    AnonymousChatService {
        inner: AutoDisconnecting {
            inner: chat_over_ws_anonymous,
        },
    }
}

pub fn chat_service<T: TransportConnector + 'static>(
    endpoint: &EndpointConnection<MultiRouteConnectionManager>,
    transport_connector: T,
    incoming_tx: tokio::sync::mpsc::Sender<ServerRequest<T::Stream>>,
    username: String,
    password: String,
) -> Chat<impl ChatServiceWithDebugInfo, impl ChatServiceWithDebugInfo> {
    let ws_service_connector = ChatOverWebSocketServiceConnector::new(
        WebSocketClientConnector::new(transport_connector, endpoint.config.clone()),
        incoming_tx,
    );
    {
        let auth_service = build_authorized_chat_service(
            &endpoint.manager,
            &ws_service_connector,
            username,
            password,
        );
        let unauth_service = build_anonymous_chat_service(&endpoint.manager, &ws_service_connector);
        Chat {
            auth_service,
            unauth_service,
        }
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::chat::{Response, ResponseProto, ResponseProtoInvalidError};
    use assert_matches::assert_matches;
    use http::{HeaderName, HeaderValue};

    pub(crate) mod shared {
        use std::fmt::Debug;
        use std::time::Duration;

        use async_trait::async_trait;
        use http::Method;
        use nonzero_ext::nonzero;

        use crate::chat::{ChatService, ChatServiceError, Request, Response};
        use crate::infra::certs::RootCertificates;
        use crate::infra::connection_manager::SingleRouteThrottlingConnectionManager;
        use crate::infra::errors::LogSafeDisplay;
        use crate::infra::reconnect::{ServiceConnector, ServiceState};
        use crate::infra::test::shared::{NoReconnectService, TIMEOUT_DURATION};
        use crate::infra::ConnectionParams;

        #[async_trait]
        impl<C> ChatService for NoReconnectService<C>
        where
            C: ServiceConnector + Send + Sync + 'static,
            C::Service: ChatService + Clone + Send + Sync + 'static,
            C::Channel: Send + Sync,
            C::ConnectError: Send + Sync + Debug + LogSafeDisplay,
            C::StartError: Send + Sync + Debug + LogSafeDisplay,
        {
            async fn send(
                &self,
                msg: Request,
                timeout: Duration,
            ) -> Result<Response, ChatServiceError> {
                match &*self.inner {
                    ServiceState::Active(service, status) if !status.is_stopped() => {
                        service.clone().send(msg, timeout).await
                    }
                    _ => Err(ChatServiceError::AllConnectionRoutesFailed { attempts: 1 }),
                }
            }

            async fn connect(&self) -> Result<(), ChatServiceError> {
                Ok(())
            }

            async fn disconnect(&self) {
                if let ServiceState::Active(_, status) = &*self.inner {
                    status.stop_service()
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
                "test",
                "test.signal.org",
                "test.signal.org",
                nonzero!(443u16),
                Default::default(),
                RootCertificates::Signal,
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
        let response: Result<Response, _> = proto.try_into();
        assert_matches!(response, Err(ResponseProtoInvalidError));
    }
}
