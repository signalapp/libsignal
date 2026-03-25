//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use atomic_take::AtomicTake;
use bytes::Bytes;
use futures_util::FutureExt as _;
use futures_util::future::BoxFuture;
use http::status::InvalidStatusCode;
use http::uri::{InvalidUri, PathAndQuery};
use http::{HeaderMap, HeaderName, HeaderValue};
use libsignal_bridge_macros::bridge_callbacks;
use libsignal_net::chat::fake::FakeChatRemote;
use libsignal_net::chat::server_requests::DisconnectCause;
use libsignal_net::chat::ws::ListenerEvent;
use libsignal_net::chat::{
    self, ChatConnection, ConnectError, ConnectionInfo, DebugInfo as ChatServiceDebugInfo,
    LanguageList, Request, Response as ChatResponse, SendError, UnauthenticatedChatHeaders,
};
use libsignal_net::connect_state::ConnectionResources;
use libsignal_net::env::constants::{CHAT_PROVISIONING_PATH, CHAT_WEBSOCKET_PATH};
use libsignal_net::env::{ConnectionConfig, Env};
use libsignal_net::infra::route::{
    DirectOrProxyMode, DirectOrProxyModeDiscriminants, DirectOrProxyProvider, RouteProvider,
    RouteProviderExt, TcpRoute, TlsRoute, UnresolvedHttpsServiceRoute,
};
use libsignal_net::infra::tcp_ssl::InvalidProxyConfig;
use libsignal_net::infra::{EnableDomainFronting, EnforceMinimumTls, OverrideNagleAlgorithm};
use libsignal_net_chat::api::{Auth as AuthConn, Unauth};
use libsignal_protocol::{IdentityKey, PreKeyBundle, Timestamp};
use static_assertions::assert_impl_all;

use crate::net::ConnectionManager;
use crate::net::remote_config::{RemoteConfig, RemoteConfigKey};
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

pub struct ProvisioningChatConnection {
    /// The possibly-still-being-constructed [`ChatConnection`].
    ///
    /// See [`AuthenticatedChatConnection::inner`] for rationale around lack of
    /// reader/writer contention.
    inner: tokio::sync::RwLock<MaybeChatConnection>,
}
bridge_as_handle!(ProvisioningChatConnection);
impl UnwindSafe for ProvisioningChatConnection {}
impl RefUnwindSafe for ProvisioningChatConnection {}

// We could Box the PendingChatConnection, but in practice this type will be on the heap anyway, and
// there won't be a ton of them allocated.
#[expect(clippy::large_enum_variant)]
enum MaybeChatConnection {
    Running(ChatConnection),
    WaitingForListener {
        runtime: tokio::runtime::Handle,
        pending: tokio::sync::Mutex<chat::PendingChatConnection>,
        grpc_overrides: HashMap<&'static str, chat::GrpcOverride>,
    },
    TemporarilyEvicted,
}

assert_impl_all!(MaybeChatConnection: Send, Sync);

impl UnauthenticatedChatConnection {
    pub async fn connect(
        connection_manager: &ConnectionManager,
        languages: LanguageList,
    ) -> Result<Self, ConnectError> {
        let pending = establish_chat_connection(
            "unauthenticated",
            connection_manager,
            CHAT_WEBSOCKET_PATH,
            Some(UnauthenticatedChatHeaders { languages }.into()),
        )
        .await?;
        let grpc_overrides = connection_manager.chat_grpc_overrides();
        Ok(Self {
            inner: MaybeChatConnection::WaitingForListener {
                runtime: tokio::runtime::Handle::current(),
                pending: pending.into(),
                grpc_overrides,
            }
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
    /// Given an HTTP Auth username of the form "{aci}" or "{aci}.{device_id}", parses and returns
    /// it.
    ///
    /// An absent device ID will be treated as device ID "1", consistent with the server's
    /// historical treatment of such usernames.
    ///
    /// Produces `None` on any other input (this is not a case where we need to know precisely what
    /// went wrong).
    pub fn parse_username(
        username: &str,
    ) -> Option<(libsignal_core::Aci, libsignal_core::DeviceId)> {
        const IMPLICIT_PRIMARY_DEVICE_ID_STR: &str = "1";
        let (aci_part, device_id_part) = username
            .rsplit_once('.')
            .unwrap_or((username, IMPLICIT_PRIMARY_DEVICE_ID_STR));
        let aci = libsignal_core::Aci::parse_from_service_id_string(aci_part)?;
        let device_id = libsignal_core::DeviceId::new_nonzero(
            std::num::NonZero::from_str(device_id_part).ok()?,
        )
        .ok()?;
        Some((aci, device_id))
    }

    pub async fn connect(
        connection_manager: &ConnectionManager,
        aci: libsignal_core::Aci,
        device_id: libsignal_core::DeviceId,
        password: String,
        receive_stories: bool,
        languages: LanguageList,
    ) -> Result<Self, ConnectError> {
        let pending = establish_chat_connection(
            "authenticated",
            connection_manager,
            CHAT_WEBSOCKET_PATH,
            Some(
                chat::AuthenticatedChatHeaders {
                    aci,
                    device_id,
                    password,
                    receive_stories: receive_stories.into(),
                    languages,
                }
                .into(),
            ),
        )
        .await?;
        let grpc_overrides = connection_manager.chat_grpc_overrides();
        Ok(Self {
            inner: MaybeChatConnection::WaitingForListener {
                runtime: tokio::runtime::Handle::current(),
                pending: pending.into(),
                grpc_overrides,
            }
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
            None,
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
            .preconnect_and_save(
                connection_manager.env.chat_domain_config.connect.service,
                route_provider,
                "preconnect",
            )
            .await?;
        Ok(())
    }

    /// Provides access to the inner ChatConnection using the [`Auth`](AuthConn) wrapper of
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
            LimitedLifetimeRef<'outer, 'inner, AuthConn<ChatConnection>>,
        ) -> BoxFuture<'inner, R>,
    {
        let guard = self.as_ref().read().await;
        let MaybeChatConnection::Running(inner) = &*guard else {
            panic!("listener was not set")
        };
        callback(LimitedLifetimeRef::from(<&AuthConn<_>>::from(inner))).await
    }
}

impl ProvisioningChatConnection {
    pub async fn connect(connection_manager: &ConnectionManager) -> Result<Self, ConnectError> {
        let pending = establish_chat_connection(
            "provisioning",
            connection_manager,
            CHAT_PROVISIONING_PATH,
            None,
        )
        .await?;
        Ok(Self {
            inner: MaybeChatConnection::WaitingForListener {
                runtime: tokio::runtime::Handle::current(),
                pending: pending.into(),
                grpc_overrides: Default::default(),
            }
            .into(),
        })
    }

    // Deliberately shadows the implementation on BridgeChatConnection, which takes the wrong kind
    // of listener. Nothing *prevents* calling that on a ProvisioningChatConnection, but it won't be
    // very useful, so don't do that.
    pub fn init_listener(&self, listener: Box<dyn ProvisioningListener>) {
        init_listener(
            &mut self.as_ref().blocking_write(),
            listener.into_event_listener(),
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

impl AsRef<tokio::sync::RwLock<MaybeChatConnection>> for ProvisioningChatConnection {
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
        init_listener(
            &mut self.as_ref().blocking_write(),
            listener.into_event_listener(),
        )
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
            MaybeChatConnection::WaitingForListener {
                runtime: _,
                pending,
                grpc_overrides: _,
            } => pending.lock().await.disconnect().await,
            MaybeChatConnection::TemporarilyEvicted => {
                unreachable!("unobservable state");
            }
        }
    }

    fn info(&self) -> ConnectionInfo {
        let guard = self.as_ref().blocking_read();
        match &*guard {
            MaybeChatConnection::Running(chat_connection) => {
                chat_connection.connection_info().clone()
            }
            MaybeChatConnection::WaitingForListener {
                runtime: _,
                pending,
                grpc_overrides: _,
            } => pending.blocking_lock().connection_info(),
            MaybeChatConnection::TemporarilyEvicted => unreachable!("unobservable state"),
        }
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
        Default::default(),
        Box::new(listener),
    )))
}

fn init_listener(connection: &mut MaybeChatConnection, listener: chat::ws::EventListener) {
    let (tokio_runtime, pending, grpc_overrides) =
        match std::mem::replace(connection, MaybeChatConnection::TemporarilyEvicted) {
            MaybeChatConnection::Running(chat_connection) => {
                *connection = MaybeChatConnection::Running(chat_connection);
                panic!("listener already set")
            }
            MaybeChatConnection::WaitingForListener {
                runtime,
                pending,
                grpc_overrides,
            } => (runtime, pending, grpc_overrides),
            MaybeChatConnection::TemporarilyEvicted => panic!("should be a temporary state"),
        };

    *connection = MaybeChatConnection::Running(ChatConnection::finish_connect(
        tokio_runtime,
        pending.into_inner(),
        grpc_overrides,
        listener,
    ))
}

pub struct FakeChatConnection(ChatConnection);

impl FakeChatConnection {
    pub fn new<'a>(
        tokio_runtime: tokio::runtime::Handle,
        listener: chat::ws::EventListener,
        alerts: impl IntoIterator<Item = &'a str>,
    ) -> (Self, FakeChatRemote) {
        let (inner, remote) = ChatConnection::new_fake(tokio_runtime, listener, alerts);
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

    pub fn into_provisioning(self) -> ProvisioningChatConnection {
        let Self(inner) = self;
        ProvisioningChatConnection {
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
        headers.as_ref(),
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
        env.chat_domain_config.connect.service,
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
    chat_headers: Option<&chat::ChatHeaders>,
) -> Result<
    DirectOrProxyProvider<
        impl RouteProvider<
            Route = UnresolvedHttpsServiceRoute<
                TlsRoute<TcpRoute<libsignal_net::infra::route::UnresolvedHost>>,
            >,
        > + use<>,
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

    let chat_connect =
        choose_chat_connection_config(env, chat_headers, &connection_manager.remote_config);

    let inner = chat_connect.route_provider_with_options(
        enable_domain_fronting,
        enforce_minimum_tls,
        OverrideNagleAlgorithm::OverrideToOff,
    );
    Ok(DirectOrProxyProvider {
        inner,
        mode: proxy_mode,
    })
}

fn choose_chat_connection_config<'a>(
    env: &'a Env<'_>,
    chat_headers: Option<&chat::ChatHeaders>,
    remote_config: &Mutex<RemoteConfig>,
) -> &'a ConnectionConfig {
    // At this time, in order to try the experimental H2 configuration:
    let default_config = &env.chat_domain_config.connect;

    if !should_use_h2(chat_headers, remote_config) {
        return default_config;
    }

    &env.experimental_chat_h2_domain_config.connect
}

fn should_use_h2(
    chat_headers: Option<&chat::ChatHeaders>,
    remote_config: &Mutex<RemoteConfig>,
) -> bool {
    // We must be opted in to H2 for this connection type.
    let required_flag = match chat_headers {
        Some(chat::ChatHeaders::Unauth(_)) => RemoteConfigKey::UseH2ForUnauthChat,
        // Preconnect calls `make_route_provider(..., None)`, so `None` should follow auth behavior.
        None | Some(chat::ChatHeaders::Auth(_)) => RemoteConfigKey::UseH2ForAuthChat,
    };

    let guard = remote_config.lock().expect("not poisoned");
    guard.is_enabled(required_flag)
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
#[bridge_callbacks(jni = "org.signal.libsignal.net.internal.BridgeChatListener")]
pub trait ChatListener: Send {
    fn received_incoming_message(
        &mut self,
        envelope: bytes::Bytes,
        timestamp: Timestamp,
        ack: ServerMessageAck,
    );
    fn received_queue_empty(&mut self);
    fn received_alerts(&mut self, alerts: Box<[String]>);
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
            chat::server_requests::ServerEvent::Alerts(alerts) => {
                self.received_alerts(alerts.into_boxed_slice())
            }
            chat::server_requests::ServerEvent::Stopped(error) => {
                self.connection_interrupted(error)
            }
        }
    }

    pub fn into_event_listener(mut self: Box<Self>) -> chat::ws::EventListener {
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

/// A trait of callbacks for different kinds of [`chat::server_requests::ProvisioningEvent`].
///
/// Done as multiple functions so we can adjust the types to be more suitable for bridging.
#[bridge_callbacks(jni = "org.signal.libsignal.net.internal.BridgeProvisioningListener")]
pub trait ProvisioningListener: Send {
    fn received_address(&mut self, address: String, send_ack: ServerMessageAck);
    fn received_envelope(&mut self, envelope: bytes::Bytes, send_ack: ServerMessageAck);
    fn connection_interrupted(&mut self, disconnect_cause: DisconnectCause);
}

impl dyn ProvisioningListener {
    /// A helper to translate from the libsignal-net enum to the separate callback methods in this
    /// trait.
    fn received_server_request(&mut self, request: chat::server_requests::ProvisioningEvent) {
        match request {
            chat::server_requests::ProvisioningEvent::ReceivedAddress { address, send_ack } => {
                self.received_address(address, ServerMessageAck::new(send_ack))
            }
            chat::server_requests::ProvisioningEvent::ReceivedEnvelope { envelope, send_ack } => {
                self.received_envelope(envelope, ServerMessageAck::new(send_ack))
            }
            chat::server_requests::ProvisioningEvent::Stopped(error) => {
                self.connection_interrupted(error)
            }
        }
    }

    pub fn into_event_listener(mut self: Box<Self>) -> chat::ws::EventListener {
        Box::new(move |event| {
            if let ListenerEvent::ReceivedAlerts(alerts) = &event {
                if !alerts.is_empty() {
                    log::warn!(
                        "unexpected alerts on provisioning connection: {}",
                        alerts.join(",")
                    );
                }
                return;
            }
            let event: chat::server_requests::ProvisioningEvent = match event.try_into() {
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

pub struct PreKeysResponse {
    pub identity_key: IdentityKey,
    pub pre_key_bundles: Vec<PreKeyBundle>,
}

#[cfg(test)]
mod test {
    use test_case::test_case;

    use super::*;

    const TEST_UUID: uuid::Uuid = uuid::uuid!("659aa5f4-a28d-fcc1-1ea1-b997537a3d95");

    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95" => Some((TEST_UUID.into(), libsignal_core::DeviceId::new(1).expect("valid"))))]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95.1" => Some((TEST_UUID.into(), libsignal_core::DeviceId::new(1).expect("valid"))))]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95.123" => Some((TEST_UUID.into(), libsignal_core::DeviceId::new(123).expect("valid"))))]
    #[test_case("659AA5F4-A28D-FCC1-1EA1-B997537A3D95.124" => Some((TEST_UUID.into(), libsignal_core::DeviceId::new(124).expect("valid"))))]
    #[test_case("659aA5f4-A28d-FcC1-1eA1-b997537A3d95.125" => Some((TEST_UUID.into(), libsignal_core::DeviceId::new(125).expect("valid"))))]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d9" => None)]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95." => None)]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95.a" => None)]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95.0" => None)]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95.2.3" => None)]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95.128" => None)]
    #[test_case("659aa5f4-a28d-fcc1-1ea1-b997537a3d95.9999" => None)]
    #[test_case(".123" => None)]
    #[test_case("a.123" => None)]
    #[test_case("a" => None)]
    fn test_parse_username(input: &str) -> Option<(libsignal_core::Aci, libsignal_core::DeviceId)> {
        AuthenticatedChatConnection::parse_username(input)
    }
}
