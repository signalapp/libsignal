//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;
use std::future::Future;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::str::FromStr;
use std::time::Duration;

use atomic_take::AtomicTake;
use bytes::Bytes;
use futures_util::FutureExt as _;
use futures_util::future::BoxFuture;
use http::status::InvalidStatusCode;
use http::uri::{InvalidUri, PathAndQuery};
use http::{HeaderMap, HeaderName, HeaderValue};
use libsignal_net::auth::Auth;
use libsignal_net::chat::fake::FakeChatRemote;
use libsignal_net::chat::server_requests::DisconnectCause;
use libsignal_net::chat::ws::ListenerEvent;
use libsignal_net::chat::{
    self, ChatConnection, ConnectError, ConnectionInfo, DebugInfo as ChatServiceDebugInfo,
    LanguageList, Request, Response as ChatResponse, SendError, UnauthenticatedChatHeaders,
};
use libsignal_net::connect_state::ConnectionResources;
use libsignal_net::env::constants::CHAT_WEBSOCKET_PATH;
use libsignal_net::infra::route::{
    DirectOrProxyMode, DirectOrProxyModeDiscriminants, DirectOrProxyProvider, RouteProvider,
    RouteProviderExt, TcpRoute, TlsRoute, UnresolvedHttpsServiceRoute,
};
use libsignal_net::infra::tcp_ssl::InvalidProxyConfig;
use libsignal_net::infra::{EnableDomainFronting, EnforceMinimumTls};
use libsignal_net_chat::api::Unauth;
use libsignal_protocol::Timestamp;
use static_assertions::assert_impl_all;

use crate::net::ConnectionManager;
use crate::net::remote_config::RemoteConfigKey;
use crate::support::LimitedLifetimeRef;
use crate::*;

pub type ChatConnectionInfo = ConnectionInfo;

bridge_as_handle!(ChatConnectionInfo);

pub struct UnauthenticatedChatConnection {
    /// The possibly-still-being-constructed [`ChatConnection`].
    ///
    /// See [`AuthenticatedChatConnection::inner`] for rationale around lack of
    /// reader/writer contention.
    inner: tokio::sync::RwLock<MaybeChatConnection>,
}
bridge_as_handle!(UnauthenticatedChatConnection);
impl UnwindSafe for UnauthenticatedChatConnection {}
impl RefUnwindSafe for UnauthenticatedChatConnection {}

pub struct AuthenticatedChatConnection {
    /// The possibly-still-being-constructed [`ChatConnection`].
    ///
    /// This is a `RwLock` so that bridging functions can always take a
    /// `&AuthenticatedChatConnection`, even when finishing construction of the
    /// `ChatConnection`. The lock will only be held in writer mode once, when
    /// finishing construction, and after that will be held in read mode, so
    /// there won't be any contention.
    inner: tokio::sync::RwLock<MaybeChatConnection>,
}
bridge_as_handle!(AuthenticatedChatConnection);
impl UnwindSafe for AuthenticatedChatConnection {}
impl RefUnwindSafe for AuthenticatedChatConnection {}

// We could Box the PendingChatConnection, but in practice this type will be on the heap anyway, and
// there won't be a ton of them allocated.
#[expect(clippy::large_enum_variant)]
enum MaybeChatConnection {
    Running(ChatConnection),
    WaitingForListener(
        tokio::runtime::Handle,
        tokio::sync::Mutex<chat::PendingChatConnection>,
    ),
    TemporarilyEvicted,
}

assert_impl_all!(MaybeChatConnection: Send, Sync);

impl UnauthenticatedChatConnection {
    pub async fn connect(
        connection_manager: &ConnectionManager,
        languages: LanguageList,
    ) -> Result<Self, ConnectError> {
        let inner = establish_chat_connection(
            "unauthenticated",
            connection_manager,
            CHAT_WEBSOCKET_PATH,
            Some(UnauthenticatedChatHeaders { languages }.into()),
        )
        .await?;
        Ok(Self {
            inner: MaybeChatConnection::WaitingForListener(
                tokio::runtime::Handle::current(),
                inner.into(),
            )
            .into(),
        })
    }

    /// Provides access to the inner ChatConnection using the [`Unauth`] wrapper of
    /// libsignal-net-chat.
    ///
    /// This callback signature unfortunately requires boxing; there is not yet Rust syntax to say
    /// "I return an unknown Future that might capture from its arguments" in closure position
    /// specifically. It's also extra complicated to promise that the result doesn't have to outlive
    /// &self; unfortunately there doesn't seem to be a simpler way to express this at this time!
    /// (e.g. `for<'inner where 'outer: 'inner>`)
    pub async fn as_typed<'outer, F, R>(&'outer self, callback: F) -> R
    where
        F: for<'inner> FnOnce(
            LimitedLifetimeRef<'outer, 'inner, Unauth<ChatConnection>>,
        ) -> BoxFuture<'inner, R>,
    {
        let guard = self.as_ref().read().await;
        let MaybeChatConnection::Running(inner) = &*guard else {
            panic!("listener was not set")
        };
        callback(LimitedLifetimeRef::from(<&Unauth<_>>::from(inner))).await
    }
}

impl AuthenticatedChatConnection {
    pub async fn connect(
        connection_manager: &ConnectionManager,
        auth: Auth,
        receive_stories: bool,
        languages: LanguageList,
    ) -> Result<Self, ConnectError> {
        let inner = establish_chat_connection(
            "authenticated",
            connection_manager,
            CHAT_WEBSOCKET_PATH,
            Some(
                chat::AuthenticatedChatHeaders {
                    auth,
                    receive_stories: receive_stories.into(),
                    languages,
                }
                .into(),
            ),
        )
        .await?;
        Ok(Self {
            inner: MaybeChatConnection::WaitingForListener(
                tokio::runtime::Handle::current(),
                inner.into(),
            )
            .into(),
        })
    }

    pub async fn preconnect(connection_manager: &ConnectionManager) -> Result<(), ConnectError> {
        let (enable_domain_fronting, enforce_minimum_tls) = {
            let endpoints_guard = connection_manager.endpoints.lock().expect("not poisoned");
            (
                endpoints_guard.enable_fronting,
                endpoints_guard.enforce_minimum_tls,
            )
        };
        let route_provider = make_route_provider(
            connection_manager,
            enable_domain_fronting,
            enforce_minimum_tls,
        )?
        .map_routes(|r| r.inner);
        let connection_resources = ConnectionResources {
            connect_state: &connection_manager.connect,
            dns_resolver: &connection_manager.dns_resolver,
            network_change_event: &connection_manager.network_change_event_tx.subscribe(),
            confirmation_header_name: None,
        };

        log::info!("preconnecting chat");
        connection_resources
            .preconnect_and_save(route_provider, "preconnect")
            .await?;
        Ok(())
    }
}

impl AsRef<tokio::sync::RwLock<MaybeChatConnection>> for AuthenticatedChatConnection {
    fn as_ref(&self) -> &tokio::sync::RwLock<MaybeChatConnection> {
        &self.inner
    }
}

impl AsRef<tokio::sync::RwLock<MaybeChatConnection>> for UnauthenticatedChatConnection {
    fn as_ref(&self) -> &tokio::sync::RwLock<MaybeChatConnection> {
        &self.inner
    }
}

pub trait BridgeChatConnection {
    fn init_listener(&self, listener: Box<dyn ChatListener>);

    fn send(
        &self,
        message: Request,
        timeout: Duration,
    ) -> impl Future<Output = Result<ChatResponse, SendError>> + Send;

    fn disconnect(&self) -> impl Future<Output = ()> + Send;

    fn info(&self) -> ConnectionInfo;
}

impl<C: AsRef<tokio::sync::RwLock<MaybeChatConnection>> + Sync> BridgeChatConnection for C {
    fn init_listener(&self, listener: Box<dyn ChatListener>) {
        init_listener(&mut self.as_ref().blocking_write(), listener)
    }

    async fn send(&self, message: Request, timeout: Duration) -> Result<ChatResponse, SendError> {
        let guard = self.as_ref().read().await;
        let MaybeChatConnection::Running(inner) = &*guard else {
            panic!("listener was not set")
        };
        inner.send(message, timeout).await
    }

    async fn disconnect(&self) {
        let guard = self.as_ref().read().await;
        match &*guard {
            MaybeChatConnection::Running(chat_connection) => chat_connection.disconnect().await,
            MaybeChatConnection::WaitingForListener(_handle, pending_chat_mutex) => {
                pending_chat_mutex.lock().await.disconnect().await
            }
            MaybeChatConnection::TemporarilyEvicted => {
                unreachable!("unobservable state");
            }
        }
    }

    fn info(&self) -> ConnectionInfo {
        let guard = self.as_ref().blocking_read();
        let connection_info = match &*guard {
            MaybeChatConnection::Running(chat_connection) => {
                chat_connection.connection_info().clone()
            }
            MaybeChatConnection::WaitingForListener(_, pending_chat_connection) => {
                pending_chat_connection.blocking_lock().connection_info()
            }
            MaybeChatConnection::TemporarilyEvicted => unreachable!("unobservable state"),
        };

        connection_info.clone()
    }
}

pub(crate) async fn connect_registration_chat(
    tokio_runtime: &tokio::runtime::Handle,
    connection_manager: &ConnectionManager,
    drop_on_disconnect: tokio::sync::oneshot::Sender<Infallible>,
) -> Result<Unauth<ChatConnection>, ConnectError> {
    let pending = establish_chat_connection(
        "registration",
        connection_manager,
        CHAT_WEBSOCKET_PATH,
        None,
    )
    .await?;

    let mut on_disconnect = Some(drop_on_disconnect);
    let listener = move |event| match event {
        ListenerEvent::Finished(_) => drop(on_disconnect.take()),
        ListenerEvent::ReceivedAlerts(_) | ListenerEvent::ReceivedMessage(_, _) => (),
    };

    Ok(Unauth(ChatConnection::finish_connect(
        tokio_runtime.clone(),
        pending,
        Box::new(listener),
    )))
}

fn init_listener(connection: &mut MaybeChatConnection, listener: Box<dyn ChatListener>) {
    let (tokio_runtime, pending) =
        match std::mem::replace(connection, MaybeChatConnection::TemporarilyEvicted) {
            MaybeChatConnection::Running(chat_connection) => {
                *connection = MaybeChatConnection::Running(chat_connection);
                panic!("listener already set")
            }
            MaybeChatConnection::WaitingForListener(tokio_runtime, pending_chat_connection) => {
                (tokio_runtime, pending_chat_connection)
            }
            MaybeChatConnection::TemporarilyEvicted => panic!("should be a temporary state"),
        };

    *connection = MaybeChatConnection::Running(ChatConnection::finish_connect(
        tokio_runtime,
        pending.into_inner(),
        listener.into_event_listener(),
    ))
}

pub struct FakeChatConnection(ChatConnection);

impl FakeChatConnection {
    pub fn new<'a>(
        tokio_runtime: tokio::runtime::Handle,
        listener: Box<dyn ChatListener>,
        alerts: impl IntoIterator<Item = &'a str>,
    ) -> (Self, FakeChatRemote) {
        let (inner, remote) =
            ChatConnection::new_fake(tokio_runtime, listener.into_event_listener(), alerts);
        (Self(inner), remote)
    }

    pub fn into_unauthenticated(self) -> UnauthenticatedChatConnection {
        let Self(inner) = self;
        UnauthenticatedChatConnection {
            inner: MaybeChatConnection::Running(inner).into(),
        }
    }

    pub fn into_authenticated(self) -> AuthenticatedChatConnection {
        let Self(inner) = self;
        AuthenticatedChatConnection {
            inner: MaybeChatConnection::Running(inner).into(),
        }
    }
}

async fn establish_chat_connection(
    kind: &'static str,
    connection_manager: &ConnectionManager,
    endpoint_path: &'static str,
    headers: Option<chat::ChatHeaders>,
) -> Result<chat::PendingChatConnection, ConnectError> {
    let ConnectionManager {
        env,
        dns_resolver,
        connect,
        user_agent,
        endpoints,
        network_change_event_tx,
        remote_config,
        ..
    } = connection_manager;

    let (enable_domain_fronting, enforce_minimum_tls) = {
        let endpoints_guard = endpoints.lock().expect("not poisoned");
        (
            endpoints_guard.enable_fronting,
            endpoints_guard.enforce_minimum_tls,
        )
    };

    let chat_connect = &env.chat_domain_config.connect;
    let connection_resources = ConnectionResources {
        connect_state: connect,
        dns_resolver,
        network_change_event: &network_change_event_tx.subscribe(),
        confirmation_header_name: chat_connect
            .confirmation_header_name
            .map(HeaderName::from_static),
    };
    let route_provider = make_route_provider(
        connection_manager,
        enable_domain_fronting,
        enforce_minimum_tls,
    )?;
    let proxy_mode = DirectOrProxyModeDiscriminants::from(&route_provider.mode);

    log::info!("connecting {kind} chat");

    let mut chat_ws_config = env.chat_ws_config;
    let timeout_millis = {
        let guard = remote_config.lock().expect("unpoisoned");
        guard.get(RemoteConfigKey::ChatRequestConnectionCheckTimeoutMilliseconds)
    };
    if let Some(timeout_millis) = timeout_millis
        .as_option()
        .and_then(|v| match u64::from_str(v) {
            Ok(v) => Some(v),
            Err(e) => {
                log::error!(
                    "bad {}: {v:?} ({e})",
                    RemoteConfigKey::ChatRequestConnectionCheckTimeoutMilliseconds
                );
                None
            }
        })
    {
        chat_ws_config.post_request_interface_check_timeout = Duration::from_millis(timeout_millis);
    }

    ChatConnection::start_connect_with(
        connection_resources,
        route_provider,
        endpoint_path,
        user_agent,
        chat_ws_config,
        headers,
        kind,
    )
    .inspect(|r| match r {
        Ok(connection) => {
            match (
                connection.connection_info().route_info.unresolved.proxy,
                proxy_mode,
            ) {
                (None, DirectOrProxyModeDiscriminants::DirectOnly)
                | (Some(_), DirectOrProxyModeDiscriminants::ProxyOnly)
                | (Some(_), DirectOrProxyModeDiscriminants::ProxyThenDirect) => {
                    log::info!("successfully connected {kind} chat")
                }
                (None, DirectOrProxyModeDiscriminants::ProxyThenDirect) => log::warn!(
                    "connected {kind} chat using a direct connection rather than the specified proxy"
                ),
                (None, DirectOrProxyModeDiscriminants::ProxyOnly) => unreachable!(
                    "made a direct connection despite using only proxy routes; this is a bug in libsignal"
                ),
                (Some(_), DirectOrProxyModeDiscriminants::DirectOnly) => unreachable!(
                    "made a proxy connection despite not having proxy config; this is a bug in libsignal"
                ),
            }
        }
        Err(e) => log::warn!("failed to connect {kind} chat: {e}"),
    })
    .await
}

fn make_route_provider(
    connection_manager: &ConnectionManager,
    enable_domain_fronting: EnableDomainFronting,
    enforce_minimum_tls: EnforceMinimumTls,
) -> Result<
    DirectOrProxyProvider<
        impl RouteProvider<
            Route = UnresolvedHttpsServiceRoute<
                TlsRoute<TcpRoute<libsignal_net::infra::route::UnresolvedHost>>,
            >,
        >,
    >,
    ConnectError,
> {
    let ConnectionManager {
        env,
        transport_connector,
        ..
    } = connection_manager;

    let proxy_mode: DirectOrProxyMode = (&*transport_connector.lock().expect("not poisoned"))
        .try_into()
        .map_err(|InvalidProxyConfig| ConnectError::InvalidConnectionConfiguration)?;

    let chat_connect = &env.chat_domain_config.connect;
    let override_nagle_algorithm = connection_manager.tcp_nagle_override();

    let inner = chat_connect.route_provider_with_options(
        enable_domain_fronting,
        enforce_minimum_tls,
        override_nagle_algorithm,
    );
    Ok(DirectOrProxyProvider {
        inner,
        mode: proxy_mode,
    })
}

pub struct HttpRequest {
    pub method: http::Method,
    pub path: PathAndQuery,
    pub body: Option<Bytes>,
    pub headers: std::sync::Mutex<HeaderMap>,
}

pub struct ResponseAndDebugInfo {
    pub response: ChatResponse,
    pub debug_info: ChatServiceDebugInfo,
}

bridge_as_handle!(HttpRequest);

/// Newtype wrapper for implementing [`TryFrom`]`
pub struct HttpMethod(http::Method);

impl TryFrom<String> for HttpMethod {
    type Error = <http::Method as FromStr>::Err;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        FromStr::from_str(&value).map(Self)
    }
}

#[derive(derive_more::Into)]
pub struct HttpStatus(http::StatusCode);

impl TryFrom<u16> for HttpStatus {
    type Error = InvalidStatusCode;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        http::StatusCode::from_u16(value).map(Self)
    }
}

impl HttpRequest {
    pub fn new(
        method: HttpMethod,
        path: String,
        body_as_slice: Option<&[u8]>,
    ) -> Result<Self, InvalidUri> {
        let body = body_as_slice.map(Bytes::copy_from_slice);
        let method = method.0;
        let path = path.try_into()?;
        Ok(HttpRequest {
            method,
            path,
            body,
            headers: Default::default(),
        })
    }

    pub fn add_header(&self, name: HeaderName, value: HeaderValue) {
        let mut guard = self.headers.lock().expect("not poisoned");
        guard.append(name, value);
    }
}

/// A trait of callbacks for different kinds of [`chat::server_requests::ServerEvent`].
///
/// Done as multiple functions so we can adjust the types to be more suitable for bridging.
pub trait ChatListener: Send {
    fn received_incoming_message(
        &mut self,
        envelope: Bytes,
        timestamp: Timestamp,
        ack: ServerMessageAck,
    );
    fn received_queue_empty(&mut self);
    fn received_alerts(&mut self, alerts: Vec<String>);
    fn connection_interrupted(&mut self, disconnect_cause: DisconnectCause);
}

impl dyn ChatListener {
    /// A helper to translate from the libsignal-net enum to the separate callback methods in this
    /// trait.
    fn received_server_request(&mut self, request: chat::server_requests::ServerEvent) {
        match request {
            chat::server_requests::ServerEvent::IncomingMessage {
                request_id: _,
                envelope,
                server_delivery_timestamp,
                send_ack,
            } => self.received_incoming_message(
                envelope,
                server_delivery_timestamp,
                ServerMessageAck::new(send_ack),
            ),
            chat::server_requests::ServerEvent::QueueEmpty => self.received_queue_empty(),
            chat::server_requests::ServerEvent::Alerts(alerts) => self.received_alerts(alerts),
            chat::server_requests::ServerEvent::Stopped(error) => {
                self.connection_interrupted(error)
            }
        }
    }

    fn into_event_listener(mut self: Box<Self>) -> Box<dyn FnMut(chat::ws::ListenerEvent) + Send> {
        Box::new(move |event| {
            let event: chat::server_requests::ServerEvent = match event.try_into() {
                Ok(event) => event,
                Err(err) => {
                    log::error!("{err}");
                    return;
                }
            };
            self.received_server_request(event);
        })
    }
}

/// Wraps a named type and a single-use guard around [`chat::server_requests::ResponseEnvelopeSender`].
pub struct ServerMessageAck {
    inner: AtomicTake<chat::server_requests::ResponseEnvelopeSender>,
}

impl ServerMessageAck {
    pub fn new(send_ack: chat::server_requests::ResponseEnvelopeSender) -> Self {
        Self {
            inner: AtomicTake::new(send_ack),
        }
    }

    pub fn take(&self) -> Option<chat::server_requests::ResponseEnvelopeSender> {
        self.inner.take()
    }
}

bridge_as_handle!(ServerMessageAck);

// `AtomicTake` disables its auto `Sync` impl by using a `PhantomData<UnsafeCell>`, but that also
// makes it `!RefUnwindSafe`. We're putting that back; because we only manipulate the `AtomicTake`
// using its atomic operations, it can never be in an invalid state.
impl std::panic::RefUnwindSafe for ServerMessageAck {}
