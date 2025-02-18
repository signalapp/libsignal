//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::{Debug, Display};
use std::sync::Arc;
use std::time::Duration;

use ::http::uri::PathAndQuery;
use ::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use async_trait::async_trait;
use futures_util::future::BoxFuture;
use futures_util::SinkExt;
use libsignal_net_infra::connection_manager::MultiRouteConnectionManager;
use libsignal_net_infra::dns::DnsResolver;
use libsignal_net_infra::route::{
    Connector, RouteProvider, RouteProviderExt, ThrottledConnection, ThrottlingConnector,
    TransportRoute, UnresolvedHttpsServiceRoute, UnresolvedWebsocketServiceRoute, WebSocketRoute,
    WebSocketRouteFragment,
};
use libsignal_net_infra::service::{Service, ServiceConnectorWithDecorator};
use libsignal_net_infra::timeouts::{MULTI_ROUTE_CONNECTION_TIMEOUT, ONE_ROUTE_CONNECTION_TIMEOUT};
use libsignal_net_infra::utils::ObservableEvent;
use libsignal_net_infra::ws::WebSocketClientConnector;
use libsignal_net_infra::{
    make_ws_config, AsHttpHeader, Connection, EndpointConnection, HttpRequestDecorator, IpType,
    TransportConnector, TransportInfo,
};
use tokio_tungstenite::WebSocketStream;

use crate::auth::Auth;
use crate::chat::ws::{ChatOverWebSocketServiceConnector, ServerEvent};
use crate::connect_state::{
    ConnectState, DefaultTransportConnector, RouteInfo, WebSocketTransportConnectorFactory,
};
use crate::env::{add_user_agent_header, ConnectionConfig, UserAgent};
use crate::proto;

mod error;
pub use error::ChatServiceError;

pub mod fake;
pub mod noise;
pub mod server_requests;
pub mod service;
pub mod ws;
pub mod ws2;

pub type MessageProto = proto::chat_websocket::WebSocketMessage;
pub type RequestProto = proto::chat_websocket::WebSocketRequestMessage;
pub type ResponseProto = proto::chat_websocket::WebSocketResponseMessage;
pub type ChatMessageType = proto::chat_websocket::web_socket_message::Type;

const RECEIVE_STORIES_HEADER_NAME: &str = "x-signal-receive-stories";

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

#[derive(Debug)]
pub struct DebugInfo {
    /// IP type of the connection that was used for the request.
    pub ip_type: Option<IpType>,
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
#[cfg_attr(test, derive(PartialEq))]
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
    pub fn send_authenticated(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> BoxFuture<'_, Result<Response, ChatServiceError>> {
        self.auth_service.send(msg, timeout)
    }

    pub fn send_unauthenticated(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> BoxFuture<'_, Result<Response, ChatServiceError>> {
        self.unauth_service.send(msg, timeout)
    }

    pub fn send_authenticated_and_debug(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> BoxFuture<'_, (Result<Response, ChatServiceError>, DebugInfo)> {
        self.auth_service.send_and_debug(msg, timeout)
    }

    pub fn send_unauthenticated_and_debug(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> BoxFuture<'_, (Result<Response, ChatServiceError>, DebugInfo)> {
        self.unauth_service.send_and_debug(msg, timeout)
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

/// Convenience trait for implementing [`ChatService`] on types that wrap
/// another implementer of `ChatService`.
///
/// Provides a blanket implementation of `ChatService` that delegates all calls
/// to `self.inner()`, and likewise for [`ChatServiceWithDebugInfo`].
trait DelegatingChatService {
    type Inner: ChatService + Send + Sync + ?Sized;
    fn inner(&self) -> &Self::Inner;
}

// Implemented without `#[async_trait]` to avoid extra `Box`ing.
impl<D: DelegatingChatService> ChatService for D {
    fn send<'life0, 'async_trait>(
        &'life0 self,
        msg: Request,
        timeout: Duration,
    ) -> BoxFuture<'async_trait, Result<Response, ChatServiceError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.inner().send(msg, timeout)
    }

    fn connect<'life0, 'async_trait>(
        &'life0 self,
    ) -> BoxFuture<'life0, Result<(), ChatServiceError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.inner().connect()
    }

    fn disconnect<'life0, 'async_trait>(&'life0 self) -> BoxFuture<'async_trait, ()>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.inner().disconnect()
    }
}

impl<D: DelegatingChatService<Inner: ChatServiceWithDebugInfo>> ChatServiceWithDebugInfo for D {
    fn send_and_debug<'life0, 'async_trait>(
        &'life0 self,
        msg: Request,
        timeout: Duration,
    ) -> BoxFuture<'async_trait, (Result<Response, ChatServiceError>, DebugInfo)>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.inner().send_and_debug(msg, timeout)
    }

    fn connect_and_debug<'life0, 'async_trait>(
        &'life0 self,
    ) -> BoxFuture<'async_trait, Result<DebugInfo, ChatServiceError>>
    where
        'life0: 'async_trait,
        Self: 'async_trait,
    {
        self.inner().connect_and_debug()
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

impl<T> DelegatingChatService for AnonymousChatService<T>
where
    T: ChatService + Send + Sync,
{
    type Inner = T;

    fn inner(&self) -> &Self::Inner {
        &self.inner
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

impl<T> DelegatingChatService for AuthorizedChatService<T>
where
    T: ChatService + Send + Sync,
{
    type Inner = T;
    fn inner(&self) -> &Self::Inner {
        &self.inner
    }
}

impl DelegatingChatService for Arc<dyn ChatService + Send + Sync> {
    type Inner = dyn ChatService + Send + Sync;

    fn inner(&self) -> &Self::Inner {
        self.as_ref()
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

impl<T> DelegatingChatService for AutoDisconnecting<T>
where
    T: ChatService + Clone + Send + Sync + 'static,
{
    type Inner = T;

    fn inner(&self) -> &Self::Inner {
        &self.inner
    }
}

impl DelegatingChatService for Arc<dyn ChatServiceWithDebugInfo + Send + Sync> {
    type Inner = dyn ChatServiceWithDebugInfo + Send + Sync;

    fn inner(&self) -> &Self::Inner {
        self.as_ref()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, derive_more::From)]
pub struct ReceiveStories(bool);

impl AsHttpHeader for ReceiveStories {
    const HEADER_NAME: HeaderName = HeaderName::from_static(RECEIVE_STORIES_HEADER_NAME);

    fn header_value(&self) -> HeaderValue {
        HeaderValue::from_static(if self.0 { "true" } else { "false" })
    }
}

fn build_authorized_chat_service(
    connection_manager_ws: &MultiRouteConnectionManager,
    service_connector_ws: &ChatOverWebSocketServiceConnector<impl TransportConnector + 'static>,
    auth: Auth,
    receive_stories: bool,
) -> AuthorizedChatService<impl ChatServiceWithDebugInfo> {
    let header_map = HeaderMap::from_iter([
        auth.as_header(),
        ReceiveStories(receive_stories).as_header(),
    ]);
    // ws authorized
    let chat_over_ws_auth = Service::new(
        ServiceConnectorWithDecorator::new(
            service_connector_ws.clone(),
            HttpRequestDecorator::Headers(header_map),
        ),
        connection_manager_ws.clone(),
        MULTI_ROUTE_CONNECTION_TIMEOUT,
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
    let chat_over_ws_anonymous = Service::new(
        service_connector_ws.clone(),
        connection_manager_ws.clone(),
        MULTI_ROUTE_CONNECTION_TIMEOUT,
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
    incoming_auth_tx: tokio::sync::mpsc::Sender<ServerEvent<T::Stream>>,
    incoming_unauth_tx: tokio::sync::mpsc::Sender<ServerEvent<T::Stream>>,
    auth: Auth,
    receive_stories: bool,
) -> Chat<impl ChatServiceWithDebugInfo, impl ChatServiceWithDebugInfo> {
    // Cannot reuse the same connector, since they lock on `incoming_tx` internally.
    let unauth_ws_connector = ChatOverWebSocketServiceConnector::new(
        WebSocketClientConnector::new(transport_connector.clone(), endpoint.config.clone()),
        incoming_unauth_tx,
    );
    let auth_ws_connector = ChatOverWebSocketServiceConnector::new(
        WebSocketClientConnector::new(transport_connector, endpoint.config.clone()),
        incoming_auth_tx,
    );
    {
        let auth_service = build_authorized_chat_service(
            &endpoint.manager,
            &auth_ws_connector,
            auth,
            receive_stories,
        );
        let unauth_service = build_anonymous_chat_service(&endpoint.manager, &unauth_ws_connector);
        Chat {
            auth_service,
            unauth_service,
        }
    }
}

pub fn endpoint_connection(
    connection_config: &ConnectionConfig,
    user_agent: &UserAgent,
    include_fallback: bool,
    network_change_event: &ObservableEvent,
) -> EndpointConnection<MultiRouteConnectionManager> {
    let chat_endpoint = PathAndQuery::from_static(crate::env::constants::WEB_SOCKET_PATH);
    let chat_connection_params = if include_fallback {
        connection_config.connection_params_with_fallback()
    } else {
        vec![connection_config.direct_connection_params()]
    };
    let chat_connection_params = add_user_agent_header(chat_connection_params, user_agent);
    let chat_ws_config = make_ws_config(chat_endpoint, ONE_ROUTE_CONNECTION_TIMEOUT);
    EndpointConnection::new_multi(
        chat_connection_params,
        ONE_ROUTE_CONNECTION_TIMEOUT,
        chat_ws_config,
        network_change_event,
    )
}

/// Information about an established connection.
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub route_info: RouteInfo,
    pub transport_info: TransportInfo,
}

pub struct ChatConnection {
    inner: self::ws2::Chat,
    connection_info: ConnectionInfo,
}

/// The type of the websocket connection over a given transport-level connection
/// used by [`ChatConnection`].
type ChatWebSocketConnection<TC> = ThrottledConnection<WebSocketStream<TC>>;

type ChatTransportConnection =
    <DefaultTransportConnector as Connector<TransportRoute, ()>>::Connection;

/// A connection to the chat service that isn't yet active.
///
/// Parameterized over the type of the transport-level connection for testing.
#[derive(Debug)]
pub struct PendingChatConnection<T = ChatTransportConnection> {
    connection: ChatWebSocketConnection<T>,
    ws_config: ws2::Config,
    route_info: RouteInfo,
    log_tag: Arc<str>,
}

pub struct AuthenticatedChatHeaders {
    pub auth: Auth,
    pub receive_stories: ReceiveStories,
}

pub type ChatServiceRoute = UnresolvedWebsocketServiceRoute;

impl ChatConnection {
    pub async fn start_connect_with<TC>(
        connect: &tokio::sync::RwLock<ConnectState<TC>>,
        resolver: &DnsResolver,
        http_route_provider: impl RouteProvider<Route = UnresolvedHttpsServiceRoute>,
        confirmation_header_name: Option<HeaderName>,
        user_agent: &UserAgent,
        ws_config: self::ws2::Config,
        auth: Option<AuthenticatedChatHeaders>,
        log_tag: &str,
    ) -> Result<PendingChatConnection, ChatServiceError>
    where
        TC: WebSocketTransportConnectorFactory<Connection = ChatTransportConnection>,
    {
        Self::start_connect_with_transport(
            connect,
            resolver,
            http_route_provider,
            confirmation_header_name,
            user_agent,
            ws_config,
            auth,
            log_tag,
        )
        .await
    }

    #[cfg_attr(feature = "test-util", visibility::make(pub))]
    async fn start_connect_with_transport<TC>(
        connect: &tokio::sync::RwLock<ConnectState<TC>>,
        resolver: &DnsResolver,
        http_route_provider: impl RouteProvider<Route = UnresolvedHttpsServiceRoute>,
        confirmation_header_name: Option<HeaderName>,
        user_agent: &UserAgent,
        ws_config: self::ws2::Config,
        auth: Option<AuthenticatedChatHeaders>,
        log_tag: &str,
    ) -> Result<PendingChatConnection<TC::Connection>, ChatServiceError>
    where
        TC: WebSocketTransportConnectorFactory,
    {
        let headers = auth
            .into_iter()
            .flat_map(
                |AuthenticatedChatHeaders {
                     auth,
                     receive_stories,
                 }| [auth.as_header(), receive_stories.as_header()],
            )
            .chain([user_agent.as_header()]);
        let ws_fragment = WebSocketRouteFragment {
            ws_config: Default::default(),
            endpoint: PathAndQuery::from_static(crate::env::constants::WEB_SOCKET_PATH),
            headers: HeaderMap::from_iter(headers),
        };
        let ws_routes = http_route_provider.map_routes(|http| WebSocketRoute {
            inner: http,
            fragment: ws_fragment.clone(),
        });

        let log_tag: Arc<str> = log_tag.into();
        let (ws_connection, route_info) = ConnectState::connect_ws(
            connect,
            ws_routes,
            (),
            // If we create multiple authenticated chat websocket connections at
            // the same time, the server will terminate earlier ones as later
            // ones complete. Throttling at the websocket connection level
            // lets us get connection parallelism at the transport level (which
            // is useful) while limiting us to one fully established connection
            // at a time.
            ThrottlingConnector::new(crate::infra::ws::Stateless, 1),
            resolver,
            confirmation_header_name.as_ref(),
            log_tag.clone(),
        )
        .await
        .map_err(ChatServiceError::from_single_connect_error)?;

        Ok(PendingChatConnection {
            connection: ws_connection,
            route_info,
            ws_config,
            log_tag,
        })
    }

    pub fn finish_connect(
        tokio_runtime: tokio::runtime::Handle,
        pending: PendingChatConnection,
        listener: ws2::EventListener,
    ) -> Self {
        let PendingChatConnection {
            connection,
            ws_config,
            route_info,
            log_tag,
        } = pending;
        Self {
            connection_info: ConnectionInfo {
                route_info,
                transport_info: connection.transport_info(),
            },
            inner: crate::chat::ws2::Chat::new(
                tokio_runtime,
                connection,
                ws_config,
                log_tag,
                listener,
            ),
        }
    }

    pub async fn send(
        &self,
        msg: Request,
        timeout: Duration,
    ) -> Result<Response, ChatServiceError> {
        let send_result = tokio::time::timeout(timeout, self.inner.send(msg))
            .await
            .map_err(|_elapsed| ChatServiceError::Timeout)?;
        Ok(send_result?)
    }

    pub async fn disconect(&self) {
        self.inner.disconnect().await
    }

    pub fn connection_info(&self) -> &ConnectionInfo {
        &self.connection_info
    }
}

impl PendingChatConnection {
    pub fn connection_info(&self) -> ConnectionInfo {
        ConnectionInfo {
            route_info: self.route_info.clone(),
            transport_info: self.connection.transport_info(),
        }
    }

    pub async fn disconnect(&mut self) {
        if let Err(error) = self.connection.close().await {
            log::error!(
                "[{}] pending chat connection disconnect failed with {error}",
                &self.log_tag
            );
        }
    }
}

impl Display for ConnectionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            transport_info:
                TransportInfo {
                    local_port,
                    ip_version,
                },
            route_info,
        } = self;
        write!(f, "from {ip_version}:{local_port} via {route_info}")
    }
}

#[cfg(any(test, feature = "test-util"))]
pub mod test_support {
    use std::sync::Arc;
    use std::time::Duration;

    use http::uri::PathAndQuery;
    use libsignal_net_infra::dns::DnsResolver;
    use libsignal_net_infra::tcp_ssl::DirectConnector;
    use libsignal_net_infra::{
        make_ws_config, ConnectionParams, EnableDomainFronting, EndpointConnection,
    };
    use tokio::sync::mpsc;

    use super::*;
    use crate::auth::Auth;
    use crate::chat::{ws2, Chat, ChatConnection, ChatServiceError, ChatServiceWithDebugInfo};
    use crate::connect_state::{ConnectState, SUGGESTED_CONNECT_CONFIG};
    use crate::env::constants::WEB_SOCKET_PATH;
    use crate::env::{Env, Svr3Env, UserAgent};
    use crate::infra::route::DirectOrProxyProvider;

    pub async fn simple_chat_connection(
        env: &Env<'static, Svr3Env<'static>>,
        filter_routes: impl Fn(&UnresolvedHttpsServiceRoute) -> bool,
    ) -> Result<ChatConnection, ChatServiceError> {
        let network_change_event = ObservableEvent::new();
        let dns_resolver =
            DnsResolver::new_with_static_fallback(env.static_fallback(), &network_change_event);

        let route_provider = DirectOrProxyProvider::maybe_proxied(
            env.chat_domain_config
                .connect
                .route_provider(EnableDomainFronting(true)),
            None,
        )
        .filter_routes(filter_routes);

        let connect = ConnectState::new(SUGGESTED_CONNECT_CONFIG);
        let user_agent = UserAgent::with_libsignal_version("test_simple_chat_connection");

        let ws_config = ws2::Config {
            initial_request_id: 0,
            local_idle_timeout: Duration::from_secs(60),
            remote_idle_timeout: Duration::from_secs(60),
        };

        let pending = ChatConnection::start_connect_with(
            &connect,
            &dns_resolver,
            route_provider,
            env.chat_domain_config
                .connect
                .confirmation_header_name
                .map(HeaderName::from_static),
            &user_agent,
            ws_config,
            None,
            "test",
        )
        .await?;

        // Just a no-op listener.
        let listener: ws2::EventListener = Box::new(|_event| {});

        let tokio_runtime = tokio::runtime::Handle::try_current().expect("can get tokio runtime");
        let chat_connection = ChatConnection::finish_connect(tokio_runtime, pending, listener);

        Ok(chat_connection)
    }

    pub type AnyChat = Chat<
        Arc<dyn ChatServiceWithDebugInfo + Send + Sync>,
        Arc<dyn ChatServiceWithDebugInfo + Send + Sync>,
    >;

    pub fn simple_chat_service(
        env: &Env<'static, Svr3Env<'static>>,
        auth: Auth,
        connection_params: Vec<ConnectionParams>,
    ) -> AnyChat {
        let one_route_connect_timeout = Duration::from_secs(5);
        let network_change_event = ObservableEvent::default();
        let dns_resolver =
            DnsResolver::new_with_static_fallback(env.static_fallback(), &network_change_event);
        let transport_connector = DirectConnector::new(dns_resolver);
        let chat_endpoint = PathAndQuery::from_static(WEB_SOCKET_PATH);
        let chat_ws_config = make_ws_config(chat_endpoint, one_route_connect_timeout);
        let connection = EndpointConnection::new_multi(
            connection_params,
            one_route_connect_timeout,
            chat_ws_config,
            &network_change_event,
        );

        let (incoming_auth_tx, _incoming_rx) = mpsc::channel(1);
        let (incoming_unauth_tx, _incoming_rx) = mpsc::channel(1);
        chat_service(
            &connection,
            transport_connector,
            incoming_auth_tx,
            incoming_unauth_tx,
            auth,
            false,
        )
        .into_dyn()
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::collections::HashMap;

    use assert_matches::assert_matches;
    use http::{HeaderName, HeaderValue};
    use libsignal_net_infra::certs::RootCertificates;
    use libsignal_net_infra::dns::lookup_result::LookupResult;
    use libsignal_net_infra::errors::TransportConnectError;
    use libsignal_net_infra::host::Host;
    use libsignal_net_infra::route::testutils::ConnectFn;
    use libsignal_net_infra::route::{
        DirectOrProxyRoute, HttpRouteFragment, HttpsTlsRoute, TcpRoute, TlsRoute, TlsRouteFragment,
        UnresolvedHost, DEFAULT_HTTPS_PORT,
    };
    use libsignal_net_infra::ws::WebSocketConnectError;
    use libsignal_net_infra::Alpn;
    use test_case::test_case;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;
    use crate::connect_state::SUGGESTED_CONNECT_CONFIG;

    pub(crate) mod shared {
        use std::fmt::Debug;
        use std::sync::Arc;
        use std::time::Duration;

        use async_trait::async_trait;
        use http::Method;
        use libsignal_net_infra::connection_manager::SingleRouteThrottlingConnectionManager;
        use libsignal_net_infra::errors::LogSafeDisplay;
        use libsignal_net_infra::host::Host;
        use libsignal_net_infra::service::{CancellationReason, ServiceConnector, ServiceState};
        use libsignal_net_infra::testutil::{NoReconnectService, TIMEOUT_DURATION};
        use libsignal_net_infra::utils::ObservableEvent;
        use libsignal_net_infra::{ConnectionParams, RouteType, TransportConnectionParams};
        use nonzero_ext::nonzero;

        use crate::certs::SIGNAL_ROOT_CERTIFICATES;
        use crate::chat::{ChatService, ChatServiceError, Request, Response};

        #[async_trait]
        impl<C> ChatService for NoReconnectService<C>
        where
            C: ServiceConnector<
                    Service: ChatService + Clone + Send + Sync + 'static,
                    Channel: Send + Sync,
                    ConnectError: Send + Sync + Debug + LogSafeDisplay,
                > + Send
                + Sync
                + 'static,
        {
            async fn send(
                &self,
                msg: Request,
                timeout: Duration,
            ) -> Result<Response, ChatServiceError> {
                match &*self.inner {
                    ServiceState::Active(service, status) if !status.is_cancelled() => {
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
                    status.cancel(CancellationReason::ExplicitDisconnect)
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
            let connection_params = {
                let hostname = "test.signal.org".into();
                let host = Host::Domain(Arc::clone(&hostname));
                ConnectionParams {
                    route_type: RouteType::Test,
                    transport: TransportConnectionParams {
                        sni: Arc::clone(&hostname),
                        tcp_host: host,
                        port: nonzero!(443u16),
                        certs: SIGNAL_ROOT_CERTIFICATES,
                    },
                    http_host: hostname,
                    http_request_decorator: Default::default(),
                    connection_confirmation_header: None,
                }
            };
            SingleRouteThrottlingConnectionManager::new(
                connection_params,
                TIMEOUT_DURATION,
                &ObservableEvent::default(),
            )
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

    fn encode_response(response: http::Response<impl AsRef<[u8]>>) -> Vec<u8> {
        let mut result = vec![];
        assert_eq!(
            response.version(),
            http::Version::HTTP_11,
            "not set up to write any other kind of response"
        );
        result.extend(
            format!(
                "HTTP/1.1 {} {}\r\n",
                response.status().as_u16(),
                response.status().canonical_reason().unwrap_or_default(),
            )
            .as_bytes(),
        );
        for (name, value) in response.headers() {
            result.extend([name.as_str().as_bytes(), b": ", value.as_bytes(), b"\r\n"].concat());
        }
        result.extend(b"\r\n");
        result.extend(response.body().as_ref());
        result
    }

    // It's easier to use this with test_case in string form.
    const CONFIRMATION_HEADER: &str = "x-really-signal";

    #[test_case(403, &[] => matches ChatServiceError::AllConnectionRoutesFailed { attempts: 1 })]
    #[test_case(403, &[(CONFIRMATION_HEADER, "1")] => matches ChatServiceError::DeviceDeregistered)]
    #[test_case(499, &[(CONFIRMATION_HEADER, "1")] => matches ChatServiceError::AppExpired)]
    #[test_case(429, &[(CONFIRMATION_HEADER, "1"), ("retry-after", "20")] => matches ChatServiceError::RetryLater { retry_after_seconds: 20 })]
    #[test_case(500, &[(CONFIRMATION_HEADER, "1"), ("retry-after", "20")] => matches ChatServiceError::RetryLater { retry_after_seconds: 20 })]
    #[test_case(429, &[("retry-after", "20")] => matches ChatServiceError::AllConnectionRoutesFailed { attempts: 1 })]
    #[tokio::test(start_paused = true)]
    async fn html_status_tests(
        status: u16,
        headers: &'static [(&'static str, &'static str)],
    ) -> ChatServiceError {
        _ = env_logger::builder().is_test(true).try_init();

        let (client, mut server) = tokio::io::duplex(1024);

        let server_task = tokio::spawn(async move {
            // Ignore any request, just serve a hardcoded response.
            let mut response = http::Response::builder().status(status);
            for &(name, value) in headers {
                response
                    .headers_mut()
                    .expect("no errors yet")
                    .append(name, HeaderValue::from_static(value));
            }
            server
                .write_all(&encode_response(response.body([]).expect("valid")))
                .await
                .expect("can write");

            let mut ignored_request = vec![];
            server
                .read_to_end(&mut ignored_request)
                .await
                .expect("can read");
        });

        let client = std::sync::Mutex::new(Some(client));
        let connect_state = ConnectState::new_with_transport_connector(
            SUGGESTED_CONNECT_CONFIG,
            ConnectFn(|_inner, _route, _log_tag| {
                std::future::ready(client.lock().expect("unpoisoned").take().ok_or(
                    WebSocketConnectError::Transport(TransportConnectError::TcpConnectionFailed),
                ))
            }),
        );

        const CHAT_DOMAIN: &str = "test.signal.org";

        let err = ChatConnection::start_connect_with_transport(
            &connect_state,
            &DnsResolver::new_from_static_map(HashMap::from_iter([(
                CHAT_DOMAIN,
                LookupResult::localhost(),
            )])),
            vec![HttpsTlsRoute {
                fragment: HttpRouteFragment {
                    host_header: CHAT_DOMAIN.into(),
                    path_prefix: "".into(),
                    front_name: None,
                },
                inner: TlsRoute {
                    fragment: TlsRouteFragment {
                        root_certs: RootCertificates::Native,
                        sni: Host::Domain(CHAT_DOMAIN.into()),
                        alpn: Some(Alpn::Http1_1),
                    },
                    inner: DirectOrProxyRoute::Direct(TcpRoute {
                        address: UnresolvedHost(CHAT_DOMAIN.into()),
                        port: DEFAULT_HTTPS_PORT,
                    }),
                },
            }],
            Some(HeaderName::from_static(CONFIRMATION_HEADER)),
            &UserAgent::with_libsignal_version("test"),
            ws2::Config {
                // We shouldn't get to timing out anyway.
                local_idle_timeout: Duration::ZERO,
                remote_idle_timeout: Duration::ZERO,
                initial_request_id: 0,
            },
            None,
            "fake chat",
        )
        .await
        .expect_err("should fail to connect");

        server_task.await.expect("clean exit");

        err
    }
}
