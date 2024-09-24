//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::panic::{self, RefUnwindSafe};
use std::str::FromStr;
use std::sync::Arc;

use atomic_take::AtomicTake;
use futures_util::stream::BoxStream;
use futures_util::StreamExt as _;
use http::status::InvalidStatusCode;
use http::uri::{InvalidUri, PathAndQuery};
use http::{HeaderMap, HeaderName, HeaderValue};
use libsignal_net::auth::Auth;
use libsignal_net::chat::{
    self, ChatServiceError, DebugInfo as ChatServiceDebugInfo, Response as ChatResponse,
};
use libsignal_protocol::Timestamp;
use tokio::sync::{mpsc, oneshot};

use crate::net::{ConnectionManager, TokioAsyncContext};
use crate::support::*;
use crate::*;

enum ChatListenerState {
    Inactive(BoxStream<'static, chat::server_requests::ServerEvent>),
    Active {
        handle: tokio::task::JoinHandle<BoxStream<'static, chat::server_requests::ServerEvent>>,
        cancel: oneshot::Sender<()>,
    },
    Cancelled(tokio::task::JoinHandle<BoxStream<'static, chat::server_requests::ServerEvent>>),
    CurrentlyBeingMutated,
}

impl ChatListenerState {
    fn cancel(&mut self) {
        match std::mem::replace(self, ChatListenerState::CurrentlyBeingMutated) {
            ChatListenerState::Active { handle, cancel } => {
                *self = ChatListenerState::Cancelled(handle);
                // Drop the previous cancel_tx to indicate cancellation.
                // (This could have been implicit, but it's an important state transition.)
                drop(cancel);
            }
            state @ (ChatListenerState::Inactive(_) | ChatListenerState::Cancelled(_)) => {
                *self = state;
            }
            ChatListenerState::CurrentlyBeingMutated => {
                unreachable!("this state should be ephemeral")
            }
        }
    }
}

pub struct Chat<T> {
    pub service: T,
    listener: std::sync::Mutex<ChatListenerState>,
    pub synthetic_request_tx:
        mpsc::Sender<chat::ws::ServerEvent<libsignal_net::infra::tcp_ssl::TcpSslConnectorStream>>,
}

type MpscPair<T> = (mpsc::Sender<T>, mpsc::Receiver<T>);
type ServerEventStreamPair =
    MpscPair<chat::ws::ServerEvent<libsignal_net::infra::tcp_ssl::TcpSslConnectorStream>>;

// These two types are the same for now, but might not be in the future.
pub struct AuthChatService(
    pub  chat::Chat<
        Arc<dyn chat::ChatServiceWithDebugInfo + Send + Sync>,
        Arc<dyn chat::ChatServiceWithDebugInfo + Send + Sync>,
    >,
);
pub struct UnauthChatService(
    pub  chat::Chat<
        Arc<dyn chat::ChatServiceWithDebugInfo + Send + Sync>,
        Arc<dyn chat::ChatServiceWithDebugInfo + Send + Sync>,
    >,
);

impl RefUnwindSafe for AuthChatService {}
impl RefUnwindSafe for UnauthChatService {}

impl<T> Chat<T> {
    fn new(service: T, (incoming_tx, incoming_rx): ServerEventStreamPair) -> Self {
        let incoming_stream = chat::server_requests::stream_incoming_messages(incoming_rx);

        Self {
            service,
            listener: std::sync::Mutex::new(ChatListenerState::Inactive(Box::pin(incoming_stream))),
            synthetic_request_tx: incoming_tx,
        }
    }

    pub fn set_listener(&self, listener: Box<dyn ChatListener>, runtime: &TokioAsyncContext) {
        use futures_util::future::Either;

        let (cancel_tx, cancel_rx) = oneshot::channel::<()>();

        let mut guard = self.listener.lock().expect("unpoisoned");
        let request_stream_future =
            match std::mem::replace(&mut *guard, ChatListenerState::CurrentlyBeingMutated) {
                ChatListenerState::Inactive(request_stream) => {
                    Either::Left(std::future::ready(Ok(request_stream)))
                }
                ChatListenerState::Active { handle, cancel } => {
                    // Drop the previous cancel_tx to indicate cancellation.
                    // (This could have been implicit, but it's an important state transition.)
                    drop(cancel);
                    Either::Right(handle)
                }
                ChatListenerState::Cancelled(handle) => Either::Right(handle),
                ChatListenerState::CurrentlyBeingMutated => {
                    unreachable!("this state should be ephemeral")
                }
            };

        // We're not using run_future here because we aren't trying to run a single task; we're
        // starting a run-loop. We *do* want that run-loop to be async so it goes to sleep when
        // there are no messages.
        let handle = runtime
            .rt
            .spawn(listener.start_listening(request_stream_future, cancel_rx));

        *guard = ChatListenerState::Active {
            handle,
            cancel: cancel_tx,
        };
        drop(guard);
    }

    pub fn clear_listener(&self) {
        self.listener.lock().expect("unpoisoned").cancel();
    }
}

impl Chat<AuthChatService> {
    pub fn new_auth(
        connection_manager: &ConnectionManager,
        auth: Auth,
        receive_stories: bool,
    ) -> Self {
        let (incoming_auth_tx, incoming_auth_rx) = mpsc::channel(1);
        let synthetic_request_tx = incoming_auth_tx.clone();

        let (incoming_unauth_tx, _incoming_unauth_rx) = mpsc::channel(1);

        let service = chat::chat_service(
            &connection_manager.chat,
            connection_manager
                .transport_connector
                .lock()
                .expect("not poisoned")
                .clone(),
            incoming_auth_tx,
            incoming_unauth_tx,
            auth,
            receive_stories,
        )
        .into_dyn();

        Self::new(
            AuthChatService(service),
            (synthetic_request_tx, incoming_auth_rx),
        )
    }
}

impl Chat<UnauthChatService> {
    pub fn new_unauth(connection_manager: &ConnectionManager) -> Self {
        let (incoming_auth_tx, _incoming_auth_rx) = mpsc::channel(1);
        let (incoming_unauth_tx, incoming_unauth_rx) = mpsc::channel(1);
        let synthetic_request_tx = incoming_unauth_tx.clone();

        let service = chat::chat_service(
            &connection_manager.chat,
            connection_manager
                .transport_connector
                .lock()
                .expect("not poisoned")
                .clone(),
            incoming_auth_tx,
            incoming_unauth_tx,
            // These will be unused because the auth service won't ever be connected.
            Auth {
                username: String::new(),
                password: String::new(),
            },
            false,
        )
        .into_dyn();

        Self::new(
            UnauthChatService(service),
            (synthetic_request_tx, incoming_unauth_rx),
        )
    }
}

pub type UnauthChat = Chat<UnauthChatService>;
pub type AuthChat = Chat<AuthChatService>;

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

bridge_as_handle!(UnauthChat);
bridge_as_handle!(AuthChat);
bridge_as_handle!(HttpRequest);

/// Newtype wrapper for implementing [`TryFrom`]`
pub struct HttpMethod(http::Method);

impl TryFrom<String> for HttpMethod {
    type Error = <http::Method as FromStr>::Err;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        FromStr::from_str(&value).map(Self)
    }
}

pub struct HttpStatus(http::StatusCode);

impl TryFrom<u16> for HttpStatus {
    type Error = InvalidStatusCode;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        http::StatusCode::from_u16(value).map(Self)
    }
}

impl From<HttpStatus> for http::StatusCode {
    fn from(value: HttpStatus) -> Self {
        value.0
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

/// A trait of callbacks for different kinds of [`chat::server_requests::ServerMessage`].
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
    fn connection_interrupted(&mut self, disconnect_cause: ChatServiceError);
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

    /// Starts a run loop to read from a stream of requests.
    ///
    /// Awaits `request_stream_future`, then loops until the stream is drained or `cancel_rx` fires.
    /// Each item in the stream is processed using [`Self::received_server_request`].
    ///
    /// Consumes `self`. Returns the remaining request stream, in case another listener will be set
    /// later.
    async fn start_listening(
        self: Box<dyn ChatListener>,
        request_stream_future: impl Future<
            Output = Result<
                BoxStream<'static, chat::server_requests::ServerEvent>,
                ::tokio::task::JoinError,
            >,
        >,
        mut cancel_rx: oneshot::Receiver<()>,
    ) -> BoxStream<'static, chat::server_requests::ServerEvent> {
        // This is normally done implicitly inside tokio::task::spawn[_blocking], but we do it
        // explicitly here to get a panic right away rather than only when the first request comes
        // in.
        let runtime =
            ::tokio::runtime::Handle::try_current().expect("must be run within a Tokio runtime");

        // Wait for the previous listener to be done.
        // If it panicked, though, the stream is now invalid, and there's not much we can do.
        let mut request_stream = request_stream_future
            .await
            .unwrap_or_else(|e| panic::resume_unwind(e.into_panic()));

        let mut listener = Some(self);
        loop {
            let next = ::tokio::select! {
                biased; // Always checking cancellation first makes it easier to test changing listeners.
                _ = &mut cancel_rx => None,
                next = request_stream.next() => next,
            };
            let Some(next) = next else {
                break;
            };

            // We won't read the next item until the first one is delivered, because order is
            // important. But we still want to jump over to a blocking thread, because we don't
            // *really* know what the app is going to do, and tokio should be able to work on other
            // properly async tasks in the mean time. (And because of this, we have to move
            // `listener` out and back into this task.)
            let mut listener_for_blocking_task = listener.take().expect("have listener");
            let blocking_task = runtime.spawn_blocking(move || {
                listener_for_blocking_task.received_server_request(next);
                listener_for_blocking_task
            });
            listener = match blocking_task.await {
                Ok(listener) => Some(listener),
                Err(e) => {
                    log::error!(
                            "chat listener panicked; no further messages will be read until a new listener is set: {}",
                            describe_panic(&e.into_panic())
                        );
                    break;
                }
            };
        }

        // Pass the stream along to the next listener, if there is one.
        request_stream
    }
}

/// Separated from [`ChatListener`] to make the allocation explicit.
///
/// This simplifies the handling in `bridge_fn` signatures.
pub trait MakeChatListener {
    fn make_listener(&self) -> Box<dyn ChatListener>;
}

/// Wraps a named type and a single-use guard around [`chat::server_requests::AckEnvelopeFuture`].
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
