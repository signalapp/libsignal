//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::panic::{self, RefUnwindSafe};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use atomic_take::AtomicTake;
use futures_util::stream::BoxStream;
use futures_util::StreamExt as _;
use http::uri::{InvalidUri, PathAndQuery};
use http::{HeaderMap, HeaderName, HeaderValue};
use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_net::chat::{
    self, ChatServiceError, DebugInfo as ChatServiceDebugInfo, Request, Response as ChatResponse,
};
use libsignal_net::infra::tcp_ssl::TcpSslConnectorStream;
use libsignal_protocol::Timestamp;
use tokio::sync::{mpsc, oneshot};

use crate::net::{ConnectionManager, TokioAsyncContext};
use crate::support::*;
use crate::*;

enum ChatListenerState {
    Inactive(BoxStream<'static, chat::server_requests::ServerMessage>),
    Active {
        handle: tokio::task::JoinHandle<BoxStream<'static, chat::server_requests::ServerMessage>>,
        cancel: oneshot::Sender<()>,
    },
    Cancelled(tokio::task::JoinHandle<BoxStream<'static, chat::server_requests::ServerMessage>>),
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

pub struct Chat {
    service: chat::Chat<
        Arc<dyn chat::ChatServiceWithDebugInfo + Send + Sync>,
        Arc<dyn chat::ChatServiceWithDebugInfo + Send + Sync>,
    >,
    listener: std::sync::Mutex<ChatListenerState>,
    #[cfg(feature = "testing-fns")]
    synthetic_request_tx: mpsc::Sender<chat::ws::ServerRequest<TcpSslConnectorStream>>,
}

impl RefUnwindSafe for Chat {}

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

bridge_handle!(Chat, clone = false);
bridge_handle!(HttpRequest, clone = false);

/// Newtype wrapper for implementing [`TryFrom`]`
struct HttpMethod(http::Method);

impl TryFrom<String> for HttpMethod {
    type Error = <http::Method as FromStr>::Err;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        FromStr::from_str(&value).map(Self)
    }
}

fn http_request_new_impl(
    method: AsType<HttpMethod, String>,
    path: String,
    body_as_slice: Option<&[u8]>,
) -> Result<HttpRequest, InvalidUri> {
    let body = body_as_slice.map(|slice| slice.to_vec().into_boxed_slice());
    let method = method.into_inner().0;
    let path = path.try_into()?;
    Ok(HttpRequest {
        method,
        path,
        body,
        headers: Default::default(),
    })
}

#[bridge_fn(ffi = false)]
fn HttpRequest_new(
    method: AsType<HttpMethod, String>,
    path: String,
    body_as_slice: Option<&[u8]>,
) -> Result<HttpRequest, InvalidUri> {
    http_request_new_impl(method, path, body_as_slice)
}

#[bridge_fn(jni = false, node = false)]
fn HttpRequest_new_with_body(
    method: AsType<HttpMethod, String>,
    path: String,
    body_as_slice: &[u8],
) -> Result<HttpRequest, InvalidUri> {
    http_request_new_impl(method, path, Some(body_as_slice))
}

#[bridge_fn(jni = false, node = false)]
fn HttpRequest_new_without_body(
    method: AsType<HttpMethod, String>,
    path: String,
) -> Result<HttpRequest, InvalidUri> {
    http_request_new_impl(method, path, None)
}

#[bridge_fn]
fn HttpRequest_add_header(
    request: &HttpRequest,
    name: AsType<HeaderName, String>,
    value: AsType<HeaderValue, String>,
) {
    let mut guard = request.headers.lock().expect("not poisoned");
    let header_key = name.into_inner();
    let header_value = value.into_inner();
    (*guard).append(header_key, header_value);
}

#[bridge_fn]
fn ChatService_new(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Chat {
    let (incoming_tx, incoming_rx) = mpsc::channel(1);
    let incoming_stream = chat::server_requests::stream_incoming_messages(incoming_rx);
    #[cfg(feature = "testing-fns")]
    let synthetic_request_tx = incoming_tx.clone();

    Chat {
        service: chat::chat_service(
            &connection_manager.chat,
            connection_manager
                .transport_connector
                .lock()
                .expect("not poisoned")
                .clone(),
            incoming_tx,
            username,
            password,
        )
        .into_dyn(),
        listener: std::sync::Mutex::new(ChatListenerState::Inactive(Box::pin(incoming_stream))),
        #[cfg(feature = "testing-fns")]
        synthetic_request_tx,
    }
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_disconnect(chat: &Chat) {
    chat.service.disconnect().await
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_connect_unauth(chat: &Chat) -> Result<ChatServiceDebugInfo, ChatServiceError> {
    chat.service.connect_unauthenticated().await
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_connect_auth(chat: &Chat) -> Result<ChatServiceDebugInfo, ChatServiceError> {
    chat.service.connect_authenticated().await
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_unauth_send(
    chat: &Chat,
    http_request: &HttpRequest,
    timeout_millis: u32,
) -> Result<ChatResponse, ChatServiceError> {
    let headers = http_request.headers.lock().expect("not poisoned").clone();
    let request = chat::Request {
        method: http_request.method.clone(),
        path: http_request.path.clone(),
        headers,
        body: http_request.body.clone(),
    };
    chat.service
        .send_unauthenticated(request, Duration::from_millis(timeout_millis.into()))
        .await
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_unauth_send_and_debug(
    chat: &Chat,
    http_request: &HttpRequest,
    timeout_millis: u32,
) -> Result<ResponseAndDebugInfo, ChatServiceError> {
    let headers = http_request.headers.lock().expect("not poisoned").clone();
    let request = chat::Request {
        method: http_request.method.clone(),
        path: http_request.path.clone(),
        headers,
        body: http_request.body.clone(),
    };
    let (result, debug_info) = chat
        .service
        .send_unauthenticated_and_debug(request, Duration::from_millis(timeout_millis.into()))
        .await;

    result.map(|response| ResponseAndDebugInfo {
        response,
        debug_info,
    })
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_auth_send(
    chat: &Chat,
    http_request: &HttpRequest,
    timeout_millis: u32,
) -> Result<ChatResponse, ChatServiceError> {
    let headers = http_request.headers.lock().expect("not poisoned").clone();
    let request = Request {
        method: http_request.method.clone(),
        path: http_request.path.clone(),
        headers,
        body: http_request.body.clone(),
    };
    chat.service
        .send_authenticated(request, Duration::from_millis(timeout_millis.into()))
        .await
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_auth_send_and_debug(
    chat: &Chat,
    http_request: &HttpRequest,
    timeout_millis: u32,
) -> Result<ResponseAndDebugInfo, ChatServiceError> {
    let headers = http_request.headers.lock().expect("not poisoned").clone();
    let request = Request {
        method: http_request.method.clone(),
        path: http_request.path.clone(),
        headers,
        body: http_request.body.clone(),
    };
    let (result, debug_info) = chat
        .service
        .send_authenticated_and_debug(request, Duration::from_millis(timeout_millis.into()))
        .await;

    result.map(|response| ResponseAndDebugInfo {
        response,
        debug_info,
    })
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
}

impl dyn ChatListener {
    /// A helper to translate from the libsignal-net enum to the separate callback methods in this
    /// trait.
    fn received_server_request(&mut self, request: chat::server_requests::ServerMessage) {
        match request {
            chat::server_requests::ServerMessage::IncomingMessage {
                request_id: _,
                envelope,
                server_delivery_timestamp,
                send_ack,
            } => self.received_incoming_message(
                envelope,
                server_delivery_timestamp,
                ServerMessageAck::new(send_ack),
            ),
            chat::server_requests::ServerMessage::QueueEmpty => self.received_queue_empty(),
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
                BoxStream<'static, chat::server_requests::ServerMessage>,
                ::tokio::task::JoinError,
            >,
        >,
        mut cancel_rx: oneshot::Receiver<()>,
    ) -> BoxStream<'static, chat::server_requests::ServerMessage> {
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

#[bridge_fn(jni = false)]
fn ChatServer_SetListener(
    runtime: &TokioAsyncContext,
    chat: &Chat,
    make_listener: Option<&dyn MakeChatListener>,
) {
    use futures_util::future::Either;

    let Some(maker) = make_listener else {
        chat.listener.lock().expect("unpoisoned").cancel();
        return;
    };

    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
    let listener = maker.make_listener();

    // Explicitly mark where we're holding the lock.
    {
        let mut guard = chat.listener.lock().expect("unpoisoned");
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
}

#[cfg(feature = "testing-fns")]
#[bridge_fn]
fn TESTING_ChatService_InjectRawServerRequest(chat: &Chat, bytes: &[u8]) {
    let request_proto = <chat::RequestProto as prost::Message>::decode(bytes)
        .expect("invalid protobuf cannot use this endpoint to test");
    chat.synthetic_request_tx
        .blocking_send(chat::ws::ServerRequest::fake(request_proto))
        .expect("not closed");
}

/// Wraps a named type and a single-use guard around [`chat::server_requests::AckEnvelopeFuture`].
pub struct ServerMessageAck {
    inner: AtomicTake<chat::server_requests::AckEnvelopeFuture>,
}

impl ServerMessageAck {
    fn new(send_ack: chat::server_requests::AckEnvelopeFuture) -> Self {
        Self {
            inner: AtomicTake::new(send_ack),
        }
    }
}

bridge_handle!(ServerMessageAck, clone = false);

// `AtomicTake` disables its auto `Sync` impl by using a `PhantomData<UnsafeCell>`, but that also
// makes it `!RefUnwindSafe`. We're putting that back; because we only manipulate the `AtomicTake`
// using its atomic operations, it can never be in an invalid state.
impl std::panic::RefUnwindSafe for ServerMessageAck {}

#[bridge_io(TokioAsyncContext)]
async fn ServerMessageAck_Send(ack: &ServerMessageAck) -> Result<(), ChatServiceError> {
    let future = ack.inner.take().expect("a message is only acked once");
    future.await
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::net::{ConnectionManager, ConnectionManager_set_proxy, Environment};
    use assert_matches::assert_matches;
    use libsignal_net::chat::ChatServiceError;

    // Normally we would write this test in the app languages, but it depends on timeouts.
    // Using a paused tokio runtime auto-advances time when there's no other work to be done.
    #[tokio::test(start_paused = true)]
    async fn cannot_connect_through_invalid_proxy() {
        let cm = ConnectionManager::new(Environment::Staging, "test-user-agent".to_string());

        assert_matches!(
            ConnectionManager_set_proxy(&cm, "signalfoundation.org".to_string(), 0),
            Err(_)
        );
        assert_matches!(
            ConnectionManager_set_proxy(&cm, "signalfoundation.org".to_string(), 100_000),
            Err(_)
        );

        assert_matches!(
            ConnectionManager_set_proxy(&cm, "signalfoundation.org".to_string(), -1),
            Err(_)
        );

        let chat = ChatService_new(&cm, "".to_string(), "".to_string());
        assert_matches!(
            ChatService_connect_unauth(&chat).await,
            Err(ChatServiceError::AllConnectionRoutesFailed { .. })
        );
    }
}
