//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::str::FromStr;
use std::time::Duration;

use atomic_take::AtomicTake;
use futures_util::FutureExt as _;
use http::status::InvalidStatusCode;
use http::uri::{InvalidUri, PathAndQuery};
use http::{HeaderMap, HeaderName, HeaderValue};
use libsignal_net::auth::Auth;
use libsignal_net::chat::fake::FakeChatRemote;
use libsignal_net::chat::server_requests::DisconnectCause;
use libsignal_net::chat::{
    self, ChatConnection, ChatServiceError, ConnectionInfo, DebugInfo as ChatServiceDebugInfo,
    Request, Response as ChatResponse,
};
use libsignal_net::infra::route::{ConnectionProxyConfig, DirectOrProxyProvider};
use libsignal_net::infra::tcp_ssl::InvalidProxyConfig;
use libsignal_protocol::Timestamp;
use static_assertions::assert_impl_all;

use crate::net::ConnectionManager;
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
    pub async fn connect(connection_manager: &ConnectionManager) -> Result<Self, ChatServiceError> {
        let inner = establish_chat_connection("unauthenticated", connection_manager, None).await?;
        log::info!("connected unauthenticated chat");
        Ok(Self {
            inner: MaybeChatConnection::WaitingForListener(
                tokio::runtime::Handle::current(),
                inner.into(),
            )
            .into(),
        })
    }
}
impl AuthenticatedChatConnection {
    pub async fn connect(
        connection_manager: &ConnectionManager,
        auth: Auth,
        receive_stories: bool,
    ) -> Result<Self, ChatServiceError> {
        let inner = establish_chat_connection(
            "authenticated",
            connection_manager,
            Some(chat::AuthenticatedChatHeaders {
                auth,
                receive_stories: receive_stories.into(),
            }),
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

    pub fn new_fake(
        tokio_runtime: tokio::runtime::Handle,
        listener: Box<dyn ChatListener>,
    ) -> (Self, FakeChatRemote) {
        let (inner, remote) =
            ChatConnection::new_fake(tokio_runtime, listener.into_event_listener());
        (
            Self {
                inner: MaybeChatConnection::Running(inner).into(),
            },
            remote,
        )
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
    ) -> impl Future<Output = Result<ChatResponse, ChatServiceError>> + Send;

    fn disconnect(&self) -> impl Future<Output = ()> + Send;

    fn info(&self) -> ConnectionInfo;
}

impl<C: AsRef<tokio::sync::RwLock<MaybeChatConnection>> + Sync> BridgeChatConnection for C {
    fn init_listener(&self, listener: Box<dyn ChatListener>) {
        init_listener(&mut self.as_ref().blocking_write(), listener)
    }

    async fn send(
        &self,
        message: Request,
        timeout: Duration,
    ) -> Result<ChatResponse, ChatServiceError> {
        let guard = self.as_ref().read().await;
        let MaybeChatConnection::Running(inner) = &*guard else {
            panic!("listener was not set")
        };
        inner.send(message, timeout).await
    }

    async fn disconnect(&self) {
        let guard = self.as_ref().read().await;
        match &*guard {
            MaybeChatConnection::Running(chat_connection) => chat_connection.disconect().await,
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

async fn establish_chat_connection(
    auth_type: &'static str,
    connection_manager: &ConnectionManager,
    auth: Option<chat::AuthenticatedChatHeaders>,
) -> Result<chat::PendingChatConnection, ChatServiceError> {
    let ConnectionManager {
        env,
        dns_resolver,
        connect,
        user_agent,
        transport_connector,
        endpoints,
        ..
    } = connection_manager;

    let proxy_config: Option<ConnectionProxyConfig> =
        (&*transport_connector.lock().expect("not poisoned"))
            .try_into()
            .map_err(|InvalidProxyConfig| ChatServiceError::InvalidConnectionConfiguration)?;

    let (ws_config, enable_domain_fronting) = {
        let endpoints_guard = endpoints.lock().expect("not poisoned");
        (
            endpoints_guard.chat.config.ws2_config(),
            endpoints_guard.enable_fronting,
        )
    };

    let libsignal_net::infra::ws2::Config {
        local_idle_timeout,
        remote_idle_disconnect_timeout,
        ..
    } = ws_config;

    let chat_connect = &env.chat_domain_config.connect;
    log::info!("connecting {auth_type} chat");

    ChatConnection::start_connect_with(
        connect,
        dns_resolver,
        DirectOrProxyProvider::maybe_proxied(
            chat_connect.route_provider(enable_domain_fronting),
            proxy_config,
        ),
        chat_connect
            .confirmation_header_name
            .map(HeaderName::from_static),
        user_agent,
        libsignal_net::chat::ws2::Config {
            local_idle_timeout,
            remote_idle_timeout: remote_idle_disconnect_timeout,
            initial_request_id: 0,
        },
        auth,
        auth_type,
    )
    .inspect(|r| match r {
        Ok(_) => log::info!("successfully connected {auth_type} chat"),
        Err(e) => log::warn!("failed to connect {auth_type} chat: {e}"),
    })
    .await
}

pub struct HttpRequest {
    pub method: http::Method,
    pub path: PathAndQuery,
    pub body: Option<Box<[u8]>>,
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
        let body = body_as_slice.map(|slice| slice.to_vec().into_boxed_slice());
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
        envelope: Vec<u8>,
        timestamp: Timestamp,
        ack: ServerMessageAck,
    );
    fn received_queue_empty(&mut self);
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
            chat::server_requests::ServerEvent::Stopped(error) => {
                self.connection_interrupted(error)
            }
        }
    }

    fn into_event_listener(mut self: Box<Self>) -> Box<dyn FnMut(chat::ws2::ListenerEvent) + Send> {
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
