//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::str::FromStr;
use std::time::Duration;

use atomic_take::AtomicTake;
use bytes::Bytes;
use futures_util::future::BoxFuture;
use futures_util::stream::BoxStream;
use futures_util::{FutureExt as _, Stream, StreamExt as _};
use http::status::InvalidStatusCode;
use http::uri::{InvalidUri, PathAndQuery};
use http::{HeaderMap, HeaderName, HeaderValue};
use libsignal_account_keys::{MEDIA_ENCRYPTION_KEY_LEN, MEDIA_ID_LEN};
use libsignal_bridge_macros::{BridgedAsValue, bridge_callbacks};
use libsignal_net::chat::fake::FakeChatRemote;
use libsignal_net::chat::server_requests::DisconnectCause;
use libsignal_net::chat::ws::ListenerEvent;
use libsignal_net::chat::{
    self, ChatConnection, ConnectError, ConnectionInfo, DebugInfo as ChatServiceDebugInfo,
    LanguageList, Request, Response as ChatResponse, SendError, UnauthenticatedChatHeaders,
};
use libsignal_net::connect_state::ConnectionResources;
use libsignal_net::env::constants::{CHAT_PROVISIONING_PATH, CHAT_WEBSOCKET_PATH};
use libsignal_net::infra::route::{
    DirectOrProxyMode, DirectOrProxyModeDiscriminants, DirectOrProxyProvider, RouteProvider,
    RouteProviderExt, TcpRoute, TlsRoute, UnresolvedHttpsServiceRoute,
};
use libsignal_net::infra::tcp_ssl::InvalidProxyConfig;
use libsignal_net::infra::{EnableDomainFronting, EnforceMinimumTls, OverrideNagleAlgorithm};
use libsignal_net_chat::api::backups::BackupAuthCredentialRejected;
use libsignal_net_chat::api::{Auth as AuthConn, RequestError, Unauth};
use libsignal_net_chat::grpc::backups::{
    CopyBackupMediaFailure, CopyBackupMediaItem, CopyBackupMediaOutcome,
};
use libsignal_net_chat::stream_util::{
    BulkPolledStream, BulkPolledStreamChunk, BulkPolledStreamTerminationReason,
};
use libsignal_protocol::{IdentityKey, PreKeyBundle, Timestamp};
use static_assertions::assert_impl_all;

use crate::net::ConnectionManager;
use crate::net::remote_config::RemoteConfigKey;
use crate::support::{AsyncMutex, BridgeVec, BridgedError, LimitedLifetimeRef};
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
bridge_as_handle!(
    UnauthenticatedChatConnection,
    swift_type = "UnauthenticatedChatConnection",
    jni_class = "org.signal.libsignal.net.UnauthenticatedChatConnection",
);
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
bridge_as_handle!(
    AuthenticatedChatConnection,
    swift_type = "AuthenticatedChatConnection",
    jni_class = "org.signal.libsignal.net.AuthenticatedChatConnection",
);
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
        pending: AsyncMutex<chat::PendingChatConnection>,
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

    pub async fn require_grpc(&self) -> Unauth<impl libsignal_net_chat::grpc::GrpcServiceProvider> {
        let guard = self.as_ref().read().await;
        let MaybeChatConnection::Running(inner) = &*guard else {
            panic!("listener was not set")
        };
        Unauth(
            inner
                .shared_h2_connection()
                .expect("requires an H2 connection"),
        )
    }

    pub fn blocking_require_grpc(
        &self,
    ) -> Unauth<impl libsignal_net_chat::grpc::GrpcServiceProvider + 'static> {
        let guard = self.as_ref().blocking_read();
        let MaybeChatConnection::Running(inner) = &*guard else {
            panic!("listener was not set")
        };
        Unauth(
            inner
                .shared_h2_connection()
                .expect("requires an H2 connection"),
        )
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

    pub async fn require_grpc(
        &self,
    ) -> AuthConn<impl libsignal_net_chat::grpc::GrpcServiceProvider> {
        let guard = self.as_ref().read().await;
        let MaybeChatConnection::Running(inner) = &*guard else {
            panic!("listener was not set")
        };
        AuthConn(
            inner
                .shared_h2_connection()
                .expect("requires an H2 connection"),
        )
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
        grpc_overrides: impl IntoIterator<Item = &'static str>,
        alerts: impl IntoIterator<Item = &'a str>,
    ) -> (Self, FakeChatRemote) {
        let (inner, remote) =
            ChatConnection::new_fake(tokio_runtime, listener, grpc_overrides, alerts);
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
                | (None, DirectOrProxyModeDiscriminants::DirectThenProxy)
                | (Some(_), DirectOrProxyModeDiscriminants::ProxyOnly)
                | (Some(_), DirectOrProxyModeDiscriminants::ProxyThenDirect)
                | (Some(_), DirectOrProxyModeDiscriminants::DirectThenProxy) => {
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

    let chat_connect = &env.chat_domain_config.connect;

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
    fn connection_interrupted(&mut self, disconnect_cause: Option<BridgedError<SendError>>);
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
                self.connection_interrupted(match error {
                    DisconnectCause::LocalDisconnect => None,
                    DisconnectCause::Error(send_error) => Some(send_error.into()),
                })
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
    fn connection_interrupted(&mut self, disconnect_cause: Option<BridgedError<SendError>>);
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
            chat::server_requests::ProvisioningEvent::Stopped(error) => self
                .connection_interrupted(match error {
                    DisconnectCause::LocalDisconnect => None,
                    DisconnectCause::Error(send_error) => Some(send_error.into()),
                }),
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

// Must be kept in sync with the app languages.
#[repr(u8)]
#[derive(derive_more::TryFrom)]
#[try_from(repr)]
pub enum UserBasedSendAuthorizationKind {
    Story,
    AccessKey,
    Group,
    UnrestrictedUnauthenticatedAccess,
}

#[derive(BridgedAsValue)]
pub struct BridgeCopyBackupMediaItem {
    pub source_attachment_cdn: i32,
    pub source_key: String,
    pub object_length: i64,
    pub media_id: [u8; MEDIA_ID_LEN],
    pub encryption_key: [u8; MEDIA_ENCRYPTION_KEY_LEN],
}

impl From<CopyBackupMediaItem> for BridgeCopyBackupMediaItem {
    fn from(value: CopyBackupMediaItem) -> Self {
        Self {
            source_attachment_cdn: value
                .source_attachment_cdn
                .try_into()
                .expect("CDN numbers are small"),
            source_key: value.source_key,
            object_length: value
                .object_length
                .try_into()
                .expect("object lengths fit in i64"),
            media_id: value.media_id,
            encryption_key: value.encryption_key,
        }
    }
}

#[derive(BridgedAsValue)]
pub struct BridgeCopyBackupMediaOutcome {
    pub media_id: [u8; MEDIA_ID_LEN],
    pub result: BridgeCopyBackupMediaResult,
}

impl From<CopyBackupMediaOutcome> for BridgeCopyBackupMediaOutcome {
    fn from(value: CopyBackupMediaOutcome) -> Self {
        Self {
            media_id: value.media_id,
            result: match value.cdn_or_failure {
                Ok(cdn) => BridgeCopyBackupMediaResult::Success {
                    cdn: cdn.try_into().expect("CDN numbers are small"),
                },
                Err(CopyBackupMediaFailure::OutOfSpace) => BridgeCopyBackupMediaResult::OutOfSpace,
                Err(CopyBackupMediaFailure::SourceNotFound) => {
                    BridgeCopyBackupMediaResult::SourceNotFound
                }
                Err(CopyBackupMediaFailure::WrongSourceLength) => {
                    BridgeCopyBackupMediaResult::WrongSourceLength
                }
            },
        }
    }
}

#[derive(BridgedAsValue)]
pub enum BridgeCopyBackupMediaResult {
    Success { cdn: i32 },
    SourceNotFound,
    WrongSourceLength,
    OutOfSpace,
}

#[derive(Debug)]
pub struct StreamCancelled;

pub struct BridgeBulkPolledStream<T, E> {
    #[expect(clippy::type_complexity)]
    state: AsyncMutex<Option<BulkPolledStream<BoxStream<'static, Result<T, E>>>>>,
    cancelled: tokio::sync::watch::Sender<bool>,
}

impl<T, E> BridgeBulkPolledStream<T, E> {
    /// Wraps `stream` for bulk-polling (and cancellation).
    ///
    /// The chunk size should be chosen based on the following criteria:
    /// - How much does bridging cost, relative to consumer-side throughput? (lower limit)
    /// - How much client memory will this allocate for a full chunk? (upper limit)
    ///
    /// It is not especially affected by
    /// - High producer-side throughput (nearly any chunk size will induce backpressure)
    /// - Low producer-side throughput (nearly any chunk size will not be reached anyway)
    /// - Producer-side latency (the first element may be delayed but hopefully the rest will arrive
    ///   soon after)
    ///
    /// The debounce time should be chosen based on the following criteria:
    /// - How much does bridging cost, relative to consumer-side throughput? (lower limit)
    /// - How long can the consumer tolerate a lack of updates, relative to producer-side
    ///   throughput? (upper limit)
    /// - How much *uneven* latency is there on the connection? (lower and upper limit)
    ///
    /// If you don't have any extra information, [`BULK_POLLED_STREAM_DEFAULT_CHUNK_SIZE`] and
    /// [`BULK_POLLED_STREAM_DEFAULT_DEBOUNCE_TIME`] were chosen to be non-terrible values for an
    /// average stream.
    pub fn new(
        stream: impl Stream<Item = Result<T, E>> + Send + 'static,
        max_chunk_size: usize,
        debounce_time: Duration,
    ) -> Self {
        Self {
            state: AsyncMutex::from(Some(BulkPolledStream::new(
                stream.boxed(),
                max_chunk_size,
                debounce_time,
            ))),
            cancelled: Default::default(),
        }
    }

    pub async fn next_chunk(&self) -> Result<BulkPolledStreamChunk<T, E>, StreamCancelled> {
        let mut cancelled = self.cancelled.subscribe();
        let lock_and_poll_stream = async {
            Ok(self
                .state
                .lock()
                .await
                .as_mut()
                .ok_or(StreamCancelled)?
                .next_chunk_unpin()
                .await)
        };

        // The "biased" isn't necessary for correctness, but it's simpler to reason about.
        tokio::select! { biased;
            _ = cancelled.wait_for(|flag| *flag) => Err(StreamCancelled),
            result = lock_and_poll_stream => result,
        }
    }

    pub fn cancel(&self) {
        // First signal any tasks to exit.
        _ = self.cancelled.send_replace(true);
        // Wait for exits, then destroy the state.
        _ = self.state.blocking_lock().take();
    }
}

/// A "reasonable" default value to use for bulk-polled streaming network APIs.
///
/// Chosen only for being neither too small (thus wasting time in the bridge layer processing many
/// small chunks) nor too large (thus allocating a bunch of memory at once).
pub const BULK_POLLED_STREAM_DEFAULT_CHUNK_SIZE: usize = 64;

/// A "reasonable" default value to use for bulk-polled streaming network APIs.
///
/// Chosen only for being neither too short (thus wasting time in the bridge layer processing many
/// small chunks) nor too long (thus delaying reporting progress in a user-visible way).
pub const BULK_POLLED_STREAM_DEFAULT_DEBOUNCE_TIME: Duration = Duration::from_millis(100);

#[derive(BridgedAsValue)]
#[bridge(arg = false)]
pub struct CopyBackupMediaNextChunk {
    pub chunk: BridgeVec<BridgeCopyBackupMediaOutcome>,
    pub termination:
        Option<BulkPolledStreamTerminationReason<RequestError<BackupAuthCredentialRejected>>>,
}

#[derive(derive_more::From, derive_more::Deref)]
pub struct CopyBackupMediaStream(
    BridgeBulkPolledStream<CopyBackupMediaOutcome, RequestError<BackupAuthCredentialRejected>>,
);

bridge_as_handle!(
    CopyBackupMediaStream,
    swift_type = "CopyBackupMediaStream",
    jni_class = "org.signal.libsignal.net.internal.CopyBackupMediaStream",
);

pub mod remote_derives {
    use libsignal_core::DeviceId;

    use super::*;

    #[derive(BridgedAsValue)]
    #[bridge(remote = libsignal_net_chat::grpc::devices::LinkedDevice)]
    #[allow(unused)]
    pub struct LinkedDeviceInternal {
        pub id: DeviceId,
        pub encrypted_name: Vec<u8>,
        pub last_seen: Timestamp,
        pub registration_id: u16,
        pub created_at_ciphertext: Vec<u8>,
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use assert_matches::assert_matches;
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

    #[tokio::test]
    async fn bulk_polled_stream_cancel_with_next_chunk_in_flight() {
        let stream = Arc::new(
            BridgeBulkPolledStream::<String, std::convert::Infallible>::new(
                futures_util::stream::pending(),
                5,
                Duration::ZERO,
            ),
        );

        let next_chunk_task = tokio::task::spawn({
            let stream = stream.clone();
            async move { stream.next_chunk().await }
        });
        // Make sure the task acquires the lock.
        tokio::task::yield_now().await;

        // Cancel from an "app" thread, the way a bridge_fn would be called.
        let (cancel_done_tx, cancel_done_rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            stream.cancel();
            _ = cancel_done_tx.send(());
        });

        () = tokio::time::timeout(Duration::from_secs(1), cancel_done_rx)
            .await
            .expect("cancel() should return promptly even with a next_chunk in flight")
            .expect("should have been explicitly signalled");

        let result = tokio::time::timeout(Duration::from_secs(1), next_chunk_task)
            .await
            .expect("in-flight next_chunk should resolve once cancelled")
            .expect("should not have panicked");
        assert_matches!(result, Err(StreamCancelled));
    }

    #[tokio::test]
    async fn bulk_polled_stream_cancel_in_advance() {
        let stream = Arc::new(
            BridgeBulkPolledStream::<String, std::convert::Infallible>::new(
                futures_util::stream::pending(),
                5,
                Duration::ZERO,
            ),
        );

        // Cancel from an "app" thread, the way a bridge_fn would be called.
        let (cancel_done_tx, cancel_done_rx) = tokio::sync::oneshot::channel();
        std::thread::spawn({
            let stream = stream.clone();
            move || {
                stream.cancel();
                _ = cancel_done_tx.send(());
            }
        });

        () = tokio::time::timeout(Duration::from_secs(1), cancel_done_rx)
            .await
            .expect("cancel() should return promptly")
            .expect("should have been explicitly signalled");

        let result = tokio::time::timeout(Duration::from_secs(1), stream.next_chunk())
            .await
            .expect("in-flight next_chunk should resolve once cancelled");
        assert_matches!(result, Err(StreamCancelled));
    }
}
