//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::any::Any;
use std::collections::HashMap;
use std::future::Future;
use std::io::ErrorKind as IoErrorKind;
use std::net::IpAddr;
use std::ops::ControlFlow;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::future::Either;
use futures_util::{FutureExt as _, Stream, StreamExt as _, pin_mut};
use http::uri::PathAndQuery;
use http::{Method, StatusCode};
use itertools::Itertools as _;
use libsignal_net_infra::TransportInfo;
use libsignal_net_infra::http_client::Http2Client;
use libsignal_net_infra::route::GetCurrentInterface;
use libsignal_net_infra::utils::NetworkChangeEvent;
use libsignal_net_infra::utils::future::SomeOrPending;
pub use libsignal_net_infra::ws::connection::FinishReason;
use libsignal_net_infra::ws::connection::Outcome;
use libsignal_net_infra::ws::{WebSocketError, WebSocketStreamLike};
use pin_project::pin_project;
use prost::Message as _;
use tokio::sync::mpsc::WeakSender;
use tokio::sync::{Mutex as TokioMutex, mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant};
use tokio_stream::wrappers::{ReceiverStream, UnboundedReceiverStream};
use tungstenite::protocol::frame::coding::CloseCode;

use crate::chat::{
    ChatMessageType, GrpcBody, MessageProto, Request, RequestProto, Response, ResponseProto,
};
use crate::env::{
    ALERT_HEADER_NAME, CONNECTED_ELSEWHERE_CLOSE_CODE, CONNECTION_INVALIDATED_CLOSE_CODE,
};
use crate::infra::ws::TextOrBinary;
use crate::infra::ws::connection::{MessageEvent, NextEventError, TungsteniteSendError};

/// Chat service avilable via a connected websocket.
///
/// This is backed by a [`tokio`] task that handles the actual interaction with
/// the remote. Outgoing requests can be sent to the task via a [`mpsc::Sender`]
/// connected to a receiver held by the task. Incoming events from the task are
/// sent to the subscribed listener.
pub struct Chat {
    /// The last known state of the backing task.
    ///
    /// Since the task can exit independently at any time, there's no guarantee
    /// that [`Chat::state`] reflects the current state.
    ///
    /// This is a [`TokioMutex`] to allow lock guards to be held across await
    /// points. If it were a regular [`Mutex`] the futures produced by methods
    /// on `Chat` would not be `Send`.
    state: TokioMutex<TaskState>,
}

/// Instantiation-time configuration for a [`Chat`] instance.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// How long to wait for incoming or outgoing messages before sending a ping
    /// to the server.
    ///
    /// If this is too high, the server might time out the connection because it
    /// has been idle too long.
    pub local_idle_timeout: Duration,

    /// How long to wait for a response to a request before checking if the connection is still on
    /// the preferred network interface.
    ///
    /// If this is too high, the check may not happen before the connection would timeout anyway,
    /// per `remote_idle_timeout`.
    pub post_request_interface_check_timeout: Duration,

    /// How long to wait for an incoming message from the server before timing
    /// out the connection.
    ///
    /// If this is too low, the connection will be closed before the server
    /// responds to a ping triggered by `local_idle_timeout`.
    pub remote_idle_timeout: Duration,

    /// The value to use as the ID for the first outgoing request.
    pub initial_request_id: u64,
}

#[derive(Debug)]
pub enum ListenerEvent {
    /// Zero or more alerts were received from the server.
    ///
    /// These are more lightweight than the full requests of [`Self::ReceivedMessage`].
    /// They're also not stateful, so "zero alerts" means "clear any previous alerts".
    ReceivedAlerts(Vec<String>),

    /// A request was received from the server.
    ///
    /// The accompanying [`Responder`] can be used to send a response for the
    /// message.
    ReceivedMessage(RequestProto, Responder),

    /// The connection to the server has ended.
    ///
    /// If the connection was gracefully closed, `Ok(())` is contained.
    /// Otherwise the [`FinishError`] describes why the connection was
    /// unexpectedly closed.
    Finished(Result<FinishReason, FinishError>),
}

/// Error that can occur during a [`Chat::send`] operation.
#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum SendError {
    /// the chat service is no longer connected
    Disconnected(DisconnectedReason),
    /// an OS-level I/O error occurred
    Io(IoErrorKind),
    /// the message is larger than the configured limit
    MessageTooLarge { size: usize, max_size: usize },
    /// a protocol-level error occurred: {0}
    Protocol(tungstenite::error::ProtocolError),
    /// the response protobuf was malformed
    InvalidResponse,
    /// the request was invalid
    InvalidRequest(InvalidRequestError),
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum DisconnectedReason {
    /// the server explicitly disconnected us because we connected elsewhere with the same credentials
    ConnectedElsewhere,
    /// the server has disconnect us because the credentials we used to connect have become invalidated
    ConnectionInvalidated,
    // the socket was closed, either by us or by the server, for some other reason.
    SocketClosed {
        #[cfg(test)] // Useful for testing but otherwise unused
        reason: &'static str,
    },
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub enum InvalidRequestError {
    InvalidHeader,
}

#[derive(Debug)]
pub enum FinishError {
    Error(TaskExitError),
    /// The task exited for an unknown reason.
    ///
    /// This should never happen, though one possible cause is that the task was
    /// unexpectedly aborted.
    Unknown,
}

/// Sends a response to an incoming [`RequestProto`] to the server.
#[derive(Debug)]
pub struct Responder {
    /// The ID of the incoming request to send a response for.
    id: u64,
    /// A sender that writes to the queue read by the spawned task.
    ///
    /// This writes to the same channel that
    /// [`TaskState::MaybeStillRunning::request_tx`] does. It's weak because we
    /// don't want incoming requests that haven't been responded to to hold the
    /// channel open; otherwise [`Chat::disconnect`] wouldn't be able to signal
    /// the task to close by just dropping its strong handle.
    ///
    /// Ideally this would be a weak MPSC one-shot sender but such a type
    /// doesn't exist. This could be a [`oneshot::Sender`] but then the task
    /// would need to bounce that into the `request_tx` channel, which is extra
    /// overhead. Instead we just enforce one-shot semantics ourselves.
    tx: mpsc::WeakUnboundedSender<OutgoingResponse>,
}

pub type EventListener = Box<dyn FnMut(ListenerEvent) + Send>;

impl Chat {
    pub fn new<T>(
        tokio_runtime: tokio::runtime::Handle,
        transport: T,
        connect_response_headers: http::HeaderMap,
        config: Config,
        connection_config: ConnectionConfig<
            impl GetCurrentInterface<Representation = IpAddr> + Send + Sync + 'static,
        >,
        shared_h2_connection: Option<Http2Client<GrpcBody>>,
        network_change_event: NetworkChangeEvent,
        mut listener: EventListener,
    ) -> Self
    where
        T: WebSocketStreamLike + Send + 'static,
    {
        let Config {
            initial_request_id,
            local_idle_timeout,
            post_request_interface_check_timeout,
            remote_idle_timeout,
        } = config;
        debug_assert_eq!(
            post_request_interface_check_timeout,
            connection_config.post_request_interface_check_timeout
        );

        Self::report_alerts(connect_response_headers, &mut listener);

        // Enable access to tokio types like Sleep, but only for the duration of this call.
        let _enable_tokio_types = tokio_runtime.enter();
        Self::new_inner(
            (
                transport,
                crate::infra::ws::Config {
                    local_idle_timeout,
                    remote_idle_ping_timeout: local_idle_timeout,
                    remote_idle_disconnect_timeout: remote_idle_timeout,
                },
            ),
            connection_config,
            shared_h2_connection,
            network_change_event,
            initial_request_id,
            listener,
            tokio_runtime,
        )
    }

    fn report_alerts(connect_response_headers: http::HeaderMap, listener: &mut EventListener) {
        let alerts = connect_response_headers
            .get_all(ALERT_HEADER_NAME)
            .iter()
            .flat_map(|value| {
                value
                    .to_str()
                    .unwrap_or("[non-ASCII alert]")
                    .split_terminator(',')
                    .map(|individual_value| individual_value.trim_ascii().to_owned())
            })
            .collect_vec();
        listener(ListenerEvent::ReceivedAlerts(alerts))
    }

    pub async fn shared_h2_connection(&self) -> Option<Http2Client<GrpcBody>> {
        let state = self.state.lock().await;
        match &*state {
            TaskState::MaybeStillRunning {
                request_tx: _,
                response_tx: _,
                task: _,
                shared_h2_connection,
            } => shared_h2_connection.clone(),
            TaskState::SignaledToEnd(_) => None,
            TaskState::Finished(_) => None,
        }
    }

    /// Sends a request to the server and waits for the response.
    ///
    /// If the request can't be sent or the response isn't received, this
    /// returns an error.
    pub async fn send(&self, request: Request) -> Result<Response, SendError> {
        let Self { state } = self;

        let Request {
            method,
            body,
            headers,
            path,
        } = request;
        let headers = headers
            .iter()
            .map(|(name, value)| value.to_str().map(|value| format!("{name}: {value}")))
            .try_collect()
            .map_err(|_| SendError::InvalidRequest(InvalidRequestError::InvalidHeader))?;

        let request = PartialRequestProto {
            verb: method,
            path,
            body: body.map(Into::into),
            headers,
        };

        send_request(state, request).await
    }

    /// Requests a graceful disconnect from the server.
    ///
    /// After this completes, new calls to [`Self::send`] will fail. Sends in
    /// progress might succeed or fail, depending on the timing of sending and
    /// receiving requests and responses.
    pub async fn disconnect(&self) {
        let mut guard = self.state.lock().await;
        // Take the existing state and leave a cheap-to-construct temporary
        // state there.
        let state = std::mem::replace(
            &mut *guard,
            TaskState::Finished(Ok(FinishReason::LocalDisconnect)),
        );

        let new_state = match state {
            TaskState::MaybeStillRunning {
                request_tx,
                response_tx,
                task,
                shared_h2_connection,
            } => {
                // Signal to the task, if it's still running, that it should
                // quit. Do this by hanging up on it, at which point it will
                // exit.
                drop((request_tx, response_tx));
                drop(shared_h2_connection);
                TaskState::SignaledToEnd(task)
            }
            state @ (TaskState::SignaledToEnd(_) | TaskState::Finished(_)) => state,
        };
        *guard = new_state
    }

    /// Returns `true` if the websocket is known to be connected.
    ///
    /// If this returns `false`, the websocket is either disconnected or in the
    /// process of being disconnected. A return value of `true` does not
    /// guarantee the next [`Chat::send`] operation will be successful.
    pub async fn is_connected(&self) -> bool {
        let mut guard = self.state.lock().await;

        match &mut *guard {
            TaskState::SignaledToEnd(_) | TaskState::Finished(_) => false,
            TaskState::MaybeStillRunning {
                request_tx: _,
                response_tx: _,
                task,
                shared_h2_connection: _,
            } => {
                if !task.is_finished() {
                    return true;
                }

                // The task finished but it wasn't observed yet. Since we're
                // here, we should update the state. This `await` will finish
                // immediately since the task is already finished!
                let finish_reason = task
                    .await
                    .unwrap_or_else(|e| Err(TaskErrorState::Panic(e.into_panic())));

                *guard = TaskState::Finished(finish_reason);

                false
            }
        }
    }

    fn new_inner(
        into_inner_connection: impl IntoInnerConnection,
        connection_config: ConnectionConfig<
            impl GetCurrentInterface<Representation = IpAddr> + Send + Sync + 'static,
        >,
        shared_h2_connection: Option<Http2Client<GrpcBody>>,
        network_change_event: NetworkChangeEvent,
        initial_request_id: u64,
        listener: EventListener,
        tokio_runtime: tokio::runtime::Handle,
    ) -> Self {
        let (request_tx, request_rx) = mpsc::channel(1);
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        let log_tag = connection_config.log_tag.clone();

        let requests_in_flight = InFlightRequests {
            outstanding_reqs: Default::default(),
            oldest_outstanding_req_sent_at: None,
            log_tag: log_tag.clone(),
        };

        let mut request_id = initial_request_id;
        let request_rx = ReceiverStream::new(request_rx).map(move |request: OutgoingRequest| {
            let id = {
                let next_id = request_id.wrapping_add(1);
                std::mem::replace(&mut request_id, next_id)
            };
            let (message, meta) = request.make_message(id);

            (message, meta)
        });
        let log_tag_for_responses = log_tag.clone();
        let response_rx = UnboundedReceiverStream::new(response_rx).map(move |response| {
            let OutgoingResponse { id, status } = response;
            log::debug!("[{log_tag_for_responses}] sending response for incoming request {id}");
            let message = response_for_status(id, status);
            (message, OutgoingMeta::ResponseToIncoming)
        });

        let inner_connection = into_inner_connection.into_inner_connection(
            tokio_stream::StreamExt::merge(request_rx, response_rx),
            log_tag,
        );

        // Wrap our watch receiver stream so that when the last sender is
        // dropped, polling the stream will return `Pending` forever.
        let network_change_event =
            tokio_stream::wrappers::WatchStream::from_changes(network_change_event)
                .chain(futures_util::stream::pending());

        let connection = ConnectionImpl {
            inner: inner_connection,
            requests_in_flight,
            network_change_event,
            config: connection_config,
            outgoing_request_tx: request_tx.downgrade(),
        };

        let task = tokio_runtime.spawn(spawned_task_body(
            connection,
            listener,
            response_tx.downgrade(),
        ));
        let state = TaskState::MaybeStillRunning {
            request_tx,
            response_tx,
            task,
            shared_h2_connection,
        };

        Self {
            state: TokioMutex::new(state),
        }
    }
}

impl Responder {
    /// Sends a response for the associated request to the server.
    ///
    /// Fails if the server definitely didn't receive the response. A return
    /// value of `Ok(())` does not guarantee that the server received the
    /// response.
    pub fn send_response(self, status: StatusCode) -> Result<(), SendError> {
        let Self { id, tx } = self;

        if let Some(tx) = tx.upgrade() {
            if let Ok(()) = tx.send(OutgoingResponse { id, status }) {
                return Ok(());
            }
        }

        Err(SendError::Disconnected(DisconnectedReason::SocketClosed {
            #[cfg(test)]
            reason: "task exited without receiving response",
        }))
    }
}

#[derive(Debug)]
enum TaskState {
    /// The task isn't known to have finished, and might still be listening for events.
    MaybeStillRunning {
        request_tx: mpsc::Sender<OutgoingRequest>,
        response_tx: mpsc::UnboundedSender<OutgoingResponse>,
        task: JoinHandle<Result<FinishReason, TaskErrorState>>,
        shared_h2_connection: Option<Http2Client<GrpcBody>>,
    },
    /// The task has been signalled to end and should be terminating soon, but
    /// not necessarily immediately.
    SignaledToEnd(JoinHandle<Result<FinishReason, TaskErrorState>>),
    /// The task has ended with the given state.
    Finished(Result<FinishReason, TaskErrorState>),
}

struct InFlightRequests {
    outstanding_reqs: HashMap<RequestId, oneshot::Sender<Result<Response, TaskSendError>>>,
    /// Tracks a single request's initial send time and the number of times it's been followed up
    /// on.
    ///
    /// ...where "followed up on" is, in practice, some kind of check to see if the connection is
    /// still active.
    oldest_outstanding_req_sent_at: Option<(RequestId, Instant, u32)>,
    log_tag: Arc<str>,
}

/// Why the task finished unexpectedly.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum TaskExitError {
    /// websocket error: {0}
    WebsocketError(#[from] NextEventError),
    /// IO error on send: {0}
    SendIo(IoErrorKind),
    /// tried to send {size}-byte message but max allowed is {max_size}
    SendTooLarge { size: usize, max_size: usize },
    /// websocket protocol error: {0}
    SendProtocol(tungstenite::error::ProtocolError),
}

/// Why an outgoing request failed.
#[derive(Debug)]
enum TaskSendError {
    /// websocket send failed
    StreamSendFailed(TungsteniteSendError),
    /// received an invalid response to request
    InvalidResponse,
}

#[derive(Debug)]
enum TaskErrorState {
    Panic(#[expect(unused)] Box<dyn Any + Send>),
    SendFailed,
    AbnormalServerClose {
        code: tungstenite::protocol::frame::coding::CloseCode,
        #[expect(unused)]
        reason: String,
    },
    ReceiveFailed,
    ServerIdleTooLong(#[expect(unused)] Duration),
    UnexpectedConnectionClose,
}

#[derive(Debug, displaydoc::Display)]
enum ChatProtocolError {
    /// received {len}-byte text message
    ReceivedTextMessage { len: usize },
    /// invalid response for request {0:?}
    InvalidResponse(RequestId),
    /// decode error: {0}
    DataError(ChatProtoDataError),
    /// response had no ID
    ResponseMissingId,
    /// request had no ID
    RequestMissingId,
}

#[derive(Debug, displaydoc::Display)]
pub(super) enum ChatProtoDataError {
    /// protobuf decode failed
    InvalidProtobuf(prost::DecodeError),
    /// unrecognized message type {0}
    InvalidMessageType(i32),
    /// request-type message has response value
    RequestHasResponse,
    /// response-type messages has request value
    ResponseHasRequest,
    /// message type was unknown
    UnknownMessageType,
    /// request was missing payload
    MissingPayload,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
struct RequestId(u64);

struct PartialRequestProto {
    verb: Method,
    path: PathAndQuery,
    body: Option<Vec<u8>>,
    headers: Vec<String>,
}

struct OutgoingRequest {
    request: PartialRequestProto,
    response_sender: oneshot::Sender<Result<Response, TaskSendError>>,
}

struct OutgoingResponse {
    id: u64,
    status: StatusCode,
}

impl OutgoingRequest {
    fn make_message(self, id: u64) -> (TextOrBinary, OutgoingMeta) {
        let Self {
            request,
            response_sender,
        } = self;
        let PartialRequestProto {
            verb,
            path,
            body,
            headers,
        } = request;
        let message = RequestProto {
            verb: Some(verb.to_string()),
            path: Some(path.to_string()),
            body: body.map(Into::into),
            headers,
            id: Some(id),
        };

        let message = TextOrBinary::Binary(
            MessageProto::from(ChatMessageProto::Request(message))
                .encode_to_vec()
                .into(),
        );
        let meta = OutgoingMeta::SentRequest(RequestId(id), response_sender);
        (message, meta)
    }
}

enum IncomingEvent {
    ReceivedRequest { id: u64, request: RequestProto },
}

#[derive(Debug)]
pub struct ConnectionConfig<GCI> {
    pub log_tag: Arc<str>,
    pub post_request_interface_check_timeout: Duration,
    pub transport_info: TransportInfo,
    pub get_current_interface: GCI,
}

#[pin_project(project = ConnectionImplProj)]
/// State for the task running a connection.
///
/// This type and its methods do not depend on being run inside of a `tokio`
/// runtime.
struct ConnectionImpl<I, GCI> {
    #[pin]
    inner: I,
    requests_in_flight: InFlightRequests,
    network_change_event: futures_util::stream::Chain<
        tokio_stream::wrappers::WatchStream<()>,
        futures_util::stream::Pending<()>,
    >,
    outgoing_request_tx: WeakSender<OutgoingRequest>,
    config: ConnectionConfig<GCI>,
}

/// The metadata for an outgoing message.
#[derive(Debug)]
enum OutgoingMeta {
    /// The message is for an outgoing request.
    SentRequest(RequestId, oneshot::Sender<Result<Response, TaskSendError>>),
    /// The message is a response to an earlier incoming request.
    ResponseToIncoming,
}

/// State for a registered [`EventListener`]
struct ListenerState {
    // only `None` when the listener is being run.
    listener: Option<EventListener>,
}

impl ListenerState {
    fn new(listener: EventListener) -> Self {
        Self {
            listener: Some(listener),
        }
    }
}

impl ListenerState {
    async fn send_event(&mut self, tokio_rt: &tokio::runtime::Handle, event: ListenerEvent) {
        let mut taken_listener = self.listener.take().expect("not running");

        // This callback might take a while, so execute it without blocking the
        // Tokio runtime.
        let returned_listener = match tokio_rt
            .spawn_blocking(move || {
                taken_listener(event);
                taken_listener
            })
            .await
        {
            Ok(listener) => listener,
            Err(_join_error) => {
                log::error!("listener panicked on event; removing it");
                Box::new(|_| ())
            }
        };

        self.listener = Some(returned_listener);
    }

    fn send_event_blocking(&mut self, event: ListenerEvent) {
        let taken_listener = self.listener.take().expect("not running");

        // If there's a panic in the listener, the event and listener won't
        // escape, and so won't be used again on this thread. That means that
        // even if unwinding breaks any invariants that they have internally,
        // those won't be visible outside the `catch_unwind` call. This is
        // notionally equivalent to using `std::thread::spawn` and then joining
        // on the created thread, but without the overhead.
        let unwind_safe = AssertUnwindSafe((event, taken_listener));

        let returned_listener = match std::panic::catch_unwind(move || {
            let _ = &unwind_safe; // Force the compiler to move the entire value into the closure.
            let AssertUnwindSafe((event, mut taken_listener)) = unwind_safe;
            (*taken_listener)(event);
            taken_listener
        }) {
            Ok(listener) => listener,
            Err(_join_error) => {
                log::error!("listener panicked on event; removing it");
                Box::new(|_| ())
            }
        };

        self.listener = Some(returned_listener);
    }
}

/// The body of the spawned task that backs a [`Chat`].
///
/// It will run until [`ConnectionImpl::handle_one_event`] returns
/// [`Outcome::Finished`].
async fn spawned_task_body<
    I: InnerConnection,
    GCI: GetCurrentInterface<Representation = IpAddr>,
>(
    connection: ConnectionImpl<I, GCI>,
    listener: EventListener,
    weak_response_tx: mpsc::WeakUnboundedSender<OutgoingResponse>,
) -> Result<FinishReason, TaskErrorState> {
    pin_mut!(connection);
    let tokio_rt = tokio::runtime::Handle::current();
    let listener_state = ListenerState::new(listener);
    let log_tag = connection.config.log_tag.clone();

    // In case the task panics, make sure the callback at least knows about the
    // disconnection.
    let mut listener_state = scopeguard::guard_on_unwind(listener_state, |mut listener_state| {
        log::error!("[{log_tag}] chat handler task exited abnormally");
        listener_state.send_event_blocking(ListenerEvent::Finished(Err(FinishError::Unknown)));
    });
    let result = loop {
        let (id, incoming_request) = match connection.as_mut().handle_one_event().await {
            Outcome::Continue(None) => continue,
            Outcome::Continue(Some(IncomingEvent::ReceivedRequest { id, request })) => {
                (id, request)
            }
            Outcome::Finished(result) => break result,
        };

        log::debug!("[{log_tag}] received incoming request from server: {id}");

        let event = ListenerEvent::ReceivedMessage(
            incoming_request,
            Responder {
                id,
                tx: weak_response_tx.clone(),
            },
        );
        listener_state.send_event(&tokio_rt, event).await;
    };
    match &result {
        Ok(reason) => log::info!("[{log_tag}] chat handler task finishing after {reason}"),
        Err(err) => log::info!("[{log_tag}] chat handler task is stopping due to {err}"),
    }
    let task_result = result.as_ref().map_err(Into::into).copied();

    // The loop is finishing. Make sure to tell the listener after disarming the
    // scope guard.
    let mut listener = scopeguard::ScopeGuard::into_inner(listener_state);
    listener
        .send_event(
            &tokio_rt,
            ListenerEvent::Finished(result.map_err(FinishError::Error)),
        )
        .await;

    task_result
}

/// Retrieves the final task error state and converts it to a `SendError`.
///
/// This function waits for the task to finish if it hasn't already, and then
/// extracts the error state. It should only be called when we know the task is
/// ending or has already ended, such as when a send operation to the task has
/// failed, or it will hold the state lock for an unboundedly long time.
async fn get_task_finish_error(state: &TokioMutex<TaskState>, _reason: &'static str) -> SendError {
    // We're holding the lock here across an await point to prevent
    // another method from also trying to wait for the task result and
    // update state.  Since the earlier send failed, the task must have
    // dropped its receiver, and it doesn't do much after that so this
    // should be a short wait.
    let mut guard = state.lock().await;
    let finished_state = wait_for_task_to_finish(&mut guard).await.as_ref();
    match finished_state {
        Ok(_) => SendError::Disconnected(DisconnectedReason::SocketClosed {
            #[cfg(test)]
            reason: _reason,
        }),
        Err(err) => SendError::from(err),
    }
}

async fn send_request(
    state: &TokioMutex<TaskState>,
    request: PartialRequestProto,
) -> Result<Response, SendError> {
    // Use a block to limit the scope of the lock guard's lifetime. We don't
    // want the lock to be held for the entire send, just the outgoing bit.
    let tx = {
        match &mut *state.lock().await {
            TaskState::MaybeStillRunning {
                request_tx,
                response_tx: _,
                task: _,
                shared_h2_connection: _,
            } => request_tx.clone(),
            TaskState::SignaledToEnd(_) => {
                return Err(SendError::Disconnected(DisconnectedReason::SocketClosed {
                    #[cfg(test)]
                    reason: "task was already signalled to end",
                }));
            }
            TaskState::Finished(Ok(_reason)) => {
                return Err(SendError::Disconnected(DisconnectedReason::SocketClosed {
                    #[cfg(test)]
                    reason: "task already ended gracefully",
                }));
            }
            TaskState::Finished(Err(err)) => return Err(SendError::from(&*err)),
        }
    };

    let (sender, receiver) = oneshot::channel();

    if tx
        .send(OutgoingRequest {
            request,
            response_sender: sender,
        })
        .await
        .is_ok()
    {
        // The request was sent, now wait for the response to be sent back.
        match receiver.await {
            Ok(response) => response.map_err(SendError::from),
            Err(_) => {
                // The sender was dropped without sending a response.
                // This happens when the connection is closed while our request is in flight.
                // Fetch the reason for the underlying connection failure, and return that as the
                // reason for the request failure, to be most useful.
                Err(get_task_finish_error(state, "response channel sender was dropped").await)
            }
        }
    } else {
        // We could not send the request at all, so the task must have ended, probably due to the connection
        // closing. Fetch the reason for the underlying connection failure, and return that as the reason for
        // the request failure.
        Err(get_task_finish_error(state, "task ended gracefully before sending request").await)
    }
}

/// Wait for the task behind `state` to finish.
///
/// This (asynchronously) blocks on joining the task! Do not call this function
/// unless the task is already known to be exiting.
async fn wait_for_task_to_finish(state: &mut TaskState) -> &Result<FinishReason, TaskErrorState> {
    let task = match state {
        TaskState::MaybeStillRunning {
            task,
            request_tx: _,
            response_tx: _,
            shared_h2_connection: _,
        } => {
            // The send can only fail if the task has ended since it owns the
            // other end of the channel.
            assert!(task.is_finished());
            task
        }
        TaskState::SignaledToEnd(task) => {
            // This can happen if a disconnect was requested
            // approximately concurrently with the server disconnecting.
            // That's not an error, but it means the task is exiting
            // soon. We can wait for that and then use the error status
            // if there is one.
            task
        }
        TaskState::Finished(finish_state) => return finish_state,
    };

    let finish_state = task
        .await
        .unwrap_or_else(|join_error| match join_error.try_into_panic() {
            Ok(panic) => Err(TaskErrorState::Panic(panic)),
            Err(join_error) => {
                unreachable!("task ended unexpectedly: {}", join_error)
            }
        });

    *state = TaskState::Finished(finish_state);
    match state {
        TaskState::Finished(finish_state) => finish_state,
        _ => unreachable!("just set"),
    }
}

impl InFlightRequests {
    fn record_send(
        &mut self,
        id: RequestId,
        response_sender: oneshot::Sender<Result<Response, TaskSendError>>,
    ) {
        let Self {
            outstanding_reqs,
            oldest_outstanding_req_sent_at,
            log_tag: _,
        } = self;
        let prev = outstanding_reqs.insert(id, response_sender);
        assert!(
            prev.is_none(),
            "tried to send a second request with ID {id}",
            id = id.0
        );
        if oldest_outstanding_req_sent_at.is_none() {
            *oldest_outstanding_req_sent_at = Some((id, Instant::now(), 0));
        }
    }

    fn finish_send(&mut self, id: RequestId, result: Result<Response, TaskSendError>) {
        let Self {
            outstanding_reqs,
            oldest_outstanding_req_sent_at,
            log_tag,
        } = self;
        if let Some(sender) = outstanding_reqs.remove(&id) {
            let _ignore_send_error = sender.send(result);
        } else {
            log::error!(
                "[{log_tag}] tried to send response to nonexistent request {}",
                id.0
            );
        }
        _ = oldest_outstanding_req_sent_at.take_if(|(oldest_id, _, _)| *oldest_id == id);
    }
}

/// Effectively a [`FnOnce`] that produces an [`InnerConnection`] impl.
///
/// This isn't just a [`FnOnce`] because the output type is generic over the
/// type of the outgoing stream. That means that the caller of
/// [`IntoInnerConnection::into_inner_connection`] gets to specify the type of
/// the outgoing stream, and is why this can't all just be a function on
/// [`InnerConnection`].
trait IntoInnerConnection {
    /// Turn `self` and an outgoing stream into an `InnerConnection` impl.
    fn into_inner_connection<R>(
        self,
        outgoing_stream: R,
        log_tag: Arc<str>,
    ) -> impl InnerConnection + Send + 'static
    where
        R: Stream<Item = (TextOrBinary, OutgoingMeta)> + Send + 'static;
}

impl<S> IntoInnerConnection for (S, crate::infra::ws::Config)
where
    S: WebSocketStreamLike + Send + 'static,
{
    fn into_inner_connection<R>(
        self,
        outgoing_stream: R,
        log_tag: Arc<str>,
    ) -> impl InnerConnection + Send + 'static
    where
        R: Stream<Item = (TextOrBinary, OutgoingMeta)> + Send + 'static,
    {
        let (stream, config) = self;
        crate::infra::ws::Connection::new(stream, outgoing_stream, config, log_tag)
    }
}

type WsEvent = Outcome<MessageEvent<OutgoingMeta>, Result<FinishReason, NextEventError>>;

/// The abstraction presented by [`crate::infra::ws::Connection`].
///
/// This exists soley to provide a mock point for testing.
trait InnerConnection {
    /// Blocks until an event is available, then returns it.
    fn handle_next_event(self: Pin<&mut Self>) -> impl Future<Output = WsEvent> + Send;
}

impl<S, R> InnerConnection for crate::infra::ws::Connection<S, R>
where
    S: WebSocketStreamLike + Send,
    R: Stream<Item = (TextOrBinary, OutgoingMeta)> + Send,
{
    fn handle_next_event(self: Pin<&mut Self>) -> impl Future<Output = WsEvent> + Send {
        crate::infra::ws::Connection::handle_next_event(self)
    }
}

/// Things that could inject additional processing while waiting for an event.
///
/// See [`ConnectionImpl::handle_interruption`].
enum ConnectionEventInterruption {
    OutstandingRequestTimeout {
        request_id: RequestId,
        request_start: Instant,
    },
    NetworkChangeEvent,
}

impl<I: InnerConnection, GCI: GetCurrentInterface<Representation = IpAddr>> ConnectionImpl<I, GCI> {
    async fn handle_one_event(
        self: Pin<&mut Self>,
    ) -> Outcome<Option<IncomingEvent>, Result<FinishReason, TaskExitError>> {
        let ConnectionImplProj {
            mut inner,
            requests_in_flight,
            network_change_event,
            config,
            outgoing_request_tx,
        } = self.project();

        let mut event_fut = std::pin::pin!(inner.as_mut().handle_next_event());

        // Poll event_fut to completion while also listening for interruptions.
        let event_to_process = loop {
            let interruption_fut = if let Some((id, start, checks_completed)) =
                requests_in_flight.oldest_outstanding_req_sent_at
            {
                // If there's a request in flight, see if it's timed out yet.
                // (Assuming the timeout value doesn't overflow Instant.)
                // Every time we complete a check and do *not* end the connection, we add one to
                // a counter; we'll continue doing checks every X seconds until the request
                // completes or we close the connection.
                let sleep = config
                    .post_request_interface_check_timeout
                    .checked_mul(checks_completed)
                    .and_then(|timeout| {
                        timeout.checked_add(config.post_request_interface_check_timeout)
                    })
                    .and_then(|timeout| start.checked_add(timeout))
                    .map(tokio::time::sleep_until);
                Either::Left(SomeOrPending::from(sleep).map(move |_| {
                    ConnectionEventInterruption::OutstandingRequestTimeout {
                        request_id: id,
                        request_start: start,
                    }
                }))
            } else {
                // If there are no requests in flight, watch for a network change so we can send an
                // artificial one.
                Either::Right(
                    network_change_event
                        .next()
                        .map(|_| ConnectionEventInterruption::NetworkChangeEvent),
                )
            };

            tokio::select! {
                inner_event = &mut event_fut => break inner_event,
                interruption = interruption_fut => match Self::handle_interruption(
                    config,
                    requests_in_flight,
                    outgoing_request_tx,
                    interruption,
                )
                .await
                {
                    ControlFlow::Continue(()) => {}
                    // Note that since we're abandoning event_fut, we must produce a Finished
                    // event, so that the websocket is not polled again.
                    ControlFlow::Break(error) => break Outcome::Finished(Err(error)),
                }
            }
        };

        Self::handle_inner_response(requests_in_flight, event_to_process)
    }

    /// Handle an "interruption" that occurred while waiting for an event from the websocket.
    ///
    /// If this returns `ControlFlow::Break`, the websocket should be shut down.
    async fn handle_interruption(
        config: &ConnectionConfig<GCI>,
        requests_in_flight: &mut InFlightRequests,
        outgoing_request_tx: &WeakSender<OutgoingRequest>,
        interruption: ConnectionEventInterruption,
    ) -> ControlFlow<NextEventError> {
        let ConnectionConfig {
            log_tag,
            post_request_interface_check_timeout: _,
            transport_info,
            get_current_interface,
        } = config;

        match interruption {
            ConnectionEventInterruption::NetworkChangeEvent => {
                debug_assert_eq!(
                    requests_in_flight.oldest_outstanding_req_sent_at, None,
                    "no events came in, so no new requests should be recorded"
                );
                if let Some(reservation) = outgoing_request_tx
                    .upgrade()
                    .as_ref()
                    .and_then(|request_tx| request_tx.try_reserve().ok())
                {
                    log::info!(
                        "[{log_tag}] sending internal keepalive to determine if connection is still usable"
                    );
                    reservation.send(OutgoingRequest {
                        request: PartialRequestProto {
                            verb: Method::GET,
                            path: PathAndQuery::from_static("/v1/keepalive"),
                            body: None,
                            headers: vec![],
                        },
                        response_sender: oneshot::channel().0,
                    });
                    log::info!("[{log_tag}] finished sending off internal keepalive");
                }
            }
            ConnectionEventInterruption::OutstandingRequestTimeout {
                request_id,
                request_start,
            } => {
                if let Some((id, _start, checks_completed)) =
                    &mut requests_in_flight.oldest_outstanding_req_sent_at
                {
                    debug_assert_eq!(
                        request_id, *id,
                        "no events came in, so nothing should have changed",
                    );
                    *checks_completed = checks_completed.saturating_add(1);
                } else {
                    debug_assert!(false, "no events came in, so nothing should have changed");
                }

                let current_default_interface_ip = get_current_interface
                    .get_interface_for(transport_info.remote_addr.ip())
                    .await;

                if current_default_interface_ip == transport_info.local_addr.ip() {
                    log::info!(
                        concat!(
                            "[{}] current connection has not responded to request ",
                            "sent {:.2?} ago; continuing to wait...",
                        ),
                        log_tag,
                        request_start.elapsed(),
                    );
                } else {
                    let elapsed = request_start.elapsed();
                    log::warn!(
                        concat!(
                            "[{}] current connection is not on the default network interface ",
                            "and failed to respond to a request within {:.2?}; disconnecting"
                        ),
                        log_tag,
                        elapsed,
                    );
                    // Synthesize a Finished event so we don't get polled again.
                    return ControlFlow::Break(NextEventError::ServerIdleTimeout(elapsed));
                }
            }
        }

        ControlFlow::Continue(())
    }

    fn handle_inner_response(
        requests_in_flight: &mut InFlightRequests,
        event: WsEvent,
    ) -> Outcome<Option<IncomingEvent>, Result<FinishReason, TaskExitError>> {
        let log_tag = &requests_in_flight.log_tag;
        match event {
            Outcome::Finished(Ok(finish)) => return Outcome::Finished(Ok(finish)),
            Outcome::Finished(Err(err)) => {
                return Outcome::Finished(Err(TaskExitError::WebsocketError(err)));
            }
            Outcome::Continue(MessageEvent::SentPing | MessageEvent::ReceivedPingPong) => {}
            Outcome::Continue(MessageEvent::SentMessage(OutgoingMeta::SentRequest(
                id,
                response_sender,
            ))) => {
                requests_in_flight.record_send(id, response_sender);
            }
            Outcome::Continue(MessageEvent::SentMessage(OutgoingMeta::ResponseToIncoming)) => {
                // The message was an outgoing response to a server request.
                // Nothing to do here.
            }
            Outcome::Continue(MessageEvent::SendFailed(meta, send_error)) => {
                let task_exit_status = match &send_error {
                    TungsteniteSendError::ConnectionAlreadyClosed => {
                        // We should never hit this if the disconnect is
                        // initiated locally.
                        Ok(FinishReason::RemoteDisconnect)
                    }
                    TungsteniteSendError::Io(error) => Err(TaskExitError::SendIo(error.kind())),
                    TungsteniteSendError::MessageTooLarge { size, max_size } => {
                        Err(TaskExitError::SendTooLarge {
                            size: *size,
                            max_size: *max_size,
                        })
                    }
                    TungsteniteSendError::WebSocketProtocol(protocol_error) => {
                        Err(TaskExitError::SendProtocol(protocol_error.clone()))
                    }
                };
                log::warn!("[{log_tag}] shutting down after send failed: {send_error}");
                match meta {
                    OutgoingMeta::SentRequest(_request_id, response_sender) => {
                        // The server isn't going to get our response to an
                        // earlier request. We choose not to signal that since
                        // even if we did return `Ok` after a successful
                        // `send()`, there's no guarantee the response actually
                        // makes it to the server.
                        let _ignore_send_error =
                            response_sender.send(Err(TaskSendError::StreamSendFailed(send_error)));
                    }
                    OutgoingMeta::ResponseToIncoming => (),
                };

                // A failure to send a message isn't necessarily indicative of a
                // permanent failure, but we can't retry and we don't want to
                // violate any ordering assumptions from the client by sending
                // subsequent messages.
                return Outcome::Finished(task_exit_status);
            }
            Outcome::Continue(MessageEvent::ReceivedMessage(message)) => {
                match ChatMessage::try_from(message) {
                    Err(
                        e @ (ChatProtocolError::DataError(_)
                        | ChatProtocolError::RequestMissingId
                        | ChatProtocolError::ResponseMissingId
                        | ChatProtocolError::ReceivedTextMessage { len: _ }),
                    ) => {
                        // The message doesn't correspond to one in-flight, so
                        // there's nothing to do here. We could be strict here
                        // and close the connection, or ignore the message and
                        // keep going. We choose the latter.
                        log::warn!("[{log_tag}] received invalid message: {e}");
                    }
                    Err(ChatProtocolError::InvalidResponse(id)) => {
                        log::warn!(
                            "[{log_tag}] received invalid response for outgoing request {id}",
                            id = id.0
                        );
                        requests_in_flight.finish_send(id, Err(TaskSendError::InvalidResponse));
                        // We could close the stream at this point but it's not
                        // clear that would be better than trying to process
                        // incoming requests.
                    }
                    Ok(ChatMessage::Response(id, response)) => {
                        log::debug!(
                            "[{log_tag}] received response for outgoing request {id}",
                            id = id.0
                        );
                        requests_in_flight.finish_send(id, Ok(response))
                    }
                    Ok(ChatMessage::Request(id, request_proto)) => {
                        return Outcome::Continue(Some(IncomingEvent::ReceivedRequest {
                            id,
                            request: request_proto,
                        }));
                    }
                }
            }
        };
        Outcome::Continue(None)
    }
}

fn response_for_status(id: u64, status: StatusCode) -> TextOrBinary {
    TextOrBinary::Binary(
        MessageProto {
            r#type: Some(ChatMessageType::Response.into()),
            response: Some(ResponseProto {
                id: Some(id),
                status: Some(status.as_u16().into()),
                message: Some(
                    status
                        .canonical_reason()
                        .expect("has canonical reason")
                        .to_string(),
                ),
                headers: vec![],
                body: None,
            }),
            request: None,
        }
        .encode_to_vec()
        .into(),
    )
}

enum ChatMessage {
    Request(u64, RequestProto),
    Response(RequestId, Response),
}

impl TryFrom<TextOrBinary> for ChatMessage {
    type Error = ChatProtocolError;

    fn try_from(message: TextOrBinary) -> Result<Self, Self::Error> {
        let data = match message {
            TextOrBinary::Text(text) => {
                return Err(ChatProtocolError::ReceivedTextMessage { len: text.len() });
            }
            TextOrBinary::Binary(data) => data,
        };

        let message = decode_and_validate(&data).map_err(ChatProtocolError::DataError)?;
        match message {
            ChatMessageProto::Request(request) => {
                let id = request.id.ok_or(ChatProtocolError::RequestMissingId)?;
                Ok(Self::Request(id, request))
            }
            ChatMessageProto::Response(response) => {
                let id = response.id.ok_or(ChatProtocolError::ResponseMissingId)?;
                let response = response
                    .try_into()
                    .map_err(|_| ChatProtocolError::InvalidResponse(RequestId(id)))?;

                Ok(ChatMessage::Response(RequestId(id), response))
            }
        }
    }
}

pub(super) enum ChatMessageProto {
    Request(RequestProto),
    Response(ResponseProto),
}

impl From<ChatMessageProto> for MessageProto {
    fn from(value: ChatMessageProto) -> Self {
        let (type_, request, response) = match value {
            ChatMessageProto::Request(request) => (ChatMessageType::Request, Some(request), None),
            ChatMessageProto::Response(response) => {
                (ChatMessageType::Response, None, Some(response))
            }
        };
        MessageProto {
            r#type: Some(type_.into()),
            request,
            response,
        }
    }
}

pub(super) fn decode_and_validate(data: &[u8]) -> Result<ChatMessageProto, ChatProtoDataError> {
    let msg = MessageProto::decode(data).map_err(ChatProtoDataError::InvalidProtobuf)?;
    let MessageProto {
        r#type,
        request,
        response,
    } = msg;

    let message_type = ChatMessageType::try_from(r#type.unwrap_or_default())
        .map_err(|e| ChatProtoDataError::InvalidMessageType(e.0))?;

    match (message_type, request, response) {
        (ChatMessageType::Unknown, _, _) => Err(ChatProtoDataError::UnknownMessageType),
        (ChatMessageType::Request, Some(req), None) => Ok(ChatMessageProto::Request(req)),
        (ChatMessageType::Response, None, Some(res)) => Ok(ChatMessageProto::Response(res)),

        (ChatMessageType::Request, None, None) | (ChatMessageType::Response, None, None) => {
            Err(ChatProtoDataError::MissingPayload)
        }
        (ChatMessageType::Request, _, Some(_)) => Err(ChatProtoDataError::RequestHasResponse),
        (ChatMessageType::Response, Some(_), _) => Err(ChatProtoDataError::ResponseHasRequest),
    }
}

impl From<&TaskErrorState> for SendError {
    fn from(value: &TaskErrorState) -> Self {
        match value {
            TaskErrorState::AbnormalServerClose { code, reason: _ } => match code {
                CloseCode::Library(CONNECTED_ELSEWHERE_CLOSE_CODE) => {
                    SendError::Disconnected(DisconnectedReason::ConnectedElsewhere)
                }
                CloseCode::Library(CONNECTION_INVALIDATED_CLOSE_CODE) => {
                    SendError::Disconnected(DisconnectedReason::ConnectionInvalidated)
                }
                _ => SendError::Disconnected(DisconnectedReason::SocketClosed {
                    #[cfg(test)]
                    reason: "server closed abnormally",
                }),
            },
            _ => SendError::Disconnected(DisconnectedReason::SocketClosed {
                #[cfg(test)]
                reason: match value {
                    TaskErrorState::SendFailed => "send failed",
                    TaskErrorState::Panic(_) => "chat task panicked",
                    // Already handled above, this is test-only code so fail-fast is desirable.
                    TaskErrorState::AbnormalServerClose { .. } => unreachable!(),
                    TaskErrorState::ReceiveFailed => "receive failed",
                    TaskErrorState::ServerIdleTooLong(_) => "server idle too long",
                    TaskErrorState::UnexpectedConnectionClose => "server closed unexpectedly",
                },
            }),
        }
    }
}

impl From<TaskSendError> for SendError {
    fn from(value: TaskSendError) -> Self {
        match value {
            TaskSendError::StreamSendFailed(send_error) => send_error.into(),
            TaskSendError::InvalidResponse => SendError::InvalidResponse,
        }
    }
}

impl From<&TaskExitError> for TaskErrorState {
    fn from(value: &TaskExitError) -> Self {
        match value {
            TaskExitError::WebsocketError(next) => match next {
                NextEventError::PingFailed(_) | NextEventError::CloseFailed(_) => Self::SendFailed,
                NextEventError::AbnormalServerClose { code, reason } => Self::AbnormalServerClose {
                    code: *code,
                    reason: reason.clone(),
                },
                NextEventError::ReceiveError(_) => Self::ReceiveFailed,
                NextEventError::ServerIdleTimeout(duration) => Self::ServerIdleTooLong(*duration),
                NextEventError::UnexpectedConnectionClose => Self::UnexpectedConnectionClose,
            },
            TaskExitError::SendIo(_)
            | TaskExitError::SendTooLarge { .. }
            | TaskExitError::SendProtocol(_) => Self::SendFailed,
        }
    }
}

impl From<TungsteniteSendError> for SendError {
    fn from(value: TungsteniteSendError) -> Self {
        (&value).into()
    }
}

impl From<&TungsteniteSendError> for SendError {
    fn from(value: &TungsteniteSendError) -> Self {
        match value {
            TungsteniteSendError::Io(io) => SendError::Io(io.kind()),
            TungsteniteSendError::ConnectionAlreadyClosed => {
                SendError::Disconnected(DisconnectedReason::SocketClosed {
                    #[cfg(test)]
                    reason: "task failure due to send failure",
                })
            }
            TungsteniteSendError::MessageTooLarge { size, max_size } => {
                SendError::MessageTooLarge {
                    size: *size,
                    max_size: *max_size,
                }
            }
            TungsteniteSendError::WebSocketProtocol(e) => SendError::Protocol(e.clone()),
        }
    }
}

impl From<TaskExitError> for crate::chat::SendError {
    fn from(value: TaskExitError) -> Self {
        crate::chat::SendError::WebSocket(match value {
            TaskExitError::WebsocketError(err) => match err {
                NextEventError::PingFailed(tungstenite_error)
                | NextEventError::CloseFailed(tungstenite_error) => tungstenite_error.into(),
                NextEventError::ReceiveError(tungstenite_error) => tungstenite_error.into(),
                NextEventError::UnexpectedConnectionClose => WebSocketError::ChannelClosed,
                NextEventError::AbnormalServerClose { code, reason: _ } => match code {
                    CloseCode::Library(CONNECTION_INVALIDATED_CLOSE_CODE) => {
                        return Self::ConnectionInvalidated;
                    }
                    CloseCode::Library(CONNECTED_ELSEWHERE_CLOSE_CODE) => {
                        return Self::ConnectedElsewhere;
                    }
                    _ => WebSocketError::ChannelClosed,
                },
                NextEventError::ServerIdleTimeout(_duration) => WebSocketError::ChannelIdleTooLong,
            },
            TaskExitError::SendIo(error_kind) => {
                WebSocketError::Io(std::io::Error::new(error_kind, "[redacted]"))
            }
            TaskExitError::SendTooLarge { size, max_size } => {
                WebSocketError::Capacity(libsignal_net_infra::ws::error::SpaceError::Capacity(
                    tungstenite::error::CapacityError::MessageTooLong { size, max_size },
                ))
            }
            TaskExitError::SendProtocol(protocol_error) => {
                WebSocketError::Protocol(protocol_error.into())
            }
        })
    }
}

impl From<SendError> for super::SendError {
    fn from(value: SendError) -> Self {
        match value {
            SendError::Disconnected(DisconnectedReason::SocketClosed { .. }) => Self::Disconnected,
            SendError::Disconnected(DisconnectedReason::ConnectedElsewhere) => {
                Self::ConnectedElsewhere
            }
            SendError::Disconnected(DisconnectedReason::ConnectionInvalidated) => {
                Self::ConnectionInvalidated
            }
            SendError::Io(error_kind) => Self::WebSocket(WebSocketError::Io(error_kind.into())),
            SendError::MessageTooLarge { size, max_size } => Self::WebSocket(
                WebSocketError::Capacity(libsignal_net_infra::ws::error::SpaceError::Capacity(
                    tungstenite::error::CapacityError::MessageTooLong { size, max_size },
                )),
            ),
            SendError::Protocol(protocol_error) => {
                Self::WebSocket(WebSocketError::Protocol(protocol_error.into()))
            }
            SendError::InvalidResponse => Self::IncomingDataInvalid,
            SendError::InvalidRequest(InvalidRequestError::InvalidHeader) => {
                Self::RequestHasInvalidHeader
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::io::Error as IoError;
    use std::net::Ipv4Addr;
    use std::sync::atomic::AtomicUsize;

    use assert_matches::assert_matches;
    use const_str::ip_addr;
    use futures::stream::FusedStream as _;
    use futures_util::stream::FuturesUnordered;
    use http::HeaderMap;
    use rand::seq::IndexedRandom;
    use rand::{Rng as _, SeedableRng};
    use test_case::test_case;
    use tokio::select;
    use tokio::sync::mpsc::error::TryRecvError;

    use super::*;

    impl Responder {
        pub(crate) fn dummy() -> Self {
            Self {
                id: 1,
                tx: tokio::sync::mpsc::unbounded_channel().0.downgrade(),
            }
        }
    }

    mod fake {
        use futures_util::future::Either;
        use futures_util::stream::FusedStream;
        use libsignal_net_infra::utils::no_network_change_events;

        use super::*;

        pub(super) const INITIAL_REQUEST_ID: u64 = 42;
        pub(super) const POST_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

        pub(super) type FakeTxRxChannels = (
            mpsc::UnboundedReceiver<OutgoingMessage>,
            mpsc::UnboundedSender<
                OutcomeOrPanic<MessageEvent<OutgoingMeta>, Result<FinishReason, NextEventError>>,
            >,
        );

        pub(super) enum OutcomeOrPanic<C, F> {
            Continue(C),
            Finished(F),
            IntentionalPanic(&'static str),
        }

        impl<C, F> From<Outcome<C, F>> for OutcomeOrPanic<C, F> {
            fn from(value: Outcome<C, F>) -> Self {
                match value {
                    Outcome::Continue(c) => Self::Continue(c),
                    Outcome::Finished(f) => Self::Finished(f),
                }
            }
        }

        pub(super) struct FakeConfig {
            pub initial_request_id: u64,
            pub post_request_interface_check_timeout: Duration,
            pub network_change_event: NetworkChangeEvent,
        }

        impl Default for FakeConfig {
            fn default() -> Self {
                Self {
                    initial_request_id: INITIAL_REQUEST_ID,
                    post_request_interface_check_timeout: POST_REQUEST_TIMEOUT,
                    network_change_event: no_network_change_events(),
                }
            }
        }

        pub(super) fn new_chat(listener: EventListener) -> (Chat, FakeTxRxChannels) {
            new_chat_with_config(
                Default::default(),
                |_| std::future::ready(Ipv4Addr::LOCALHOST.into()),
                listener,
            )
        }
        pub(super) fn new_chat_with_config(
            config: FakeConfig,
            get_current_interface: impl GetCurrentInterface<Representation = IpAddr>
            + Send
            + Sync
            + 'static,
            listener: EventListener,
        ) -> (Chat, FakeTxRxChannels) {
            let FakeConfig {
                initial_request_id,
                post_request_interface_check_timeout,
                network_change_event,
            } = config;
            let (outgoing_events_tx, outgoing_events_rx) = mpsc::unbounded_channel();
            let (incoming_events_tx, incoming_events_rx) = mpsc::unbounded_channel();
            let chat = Chat::new_inner(
                IntoFakeInnerConnection {
                    outgoing_events: outgoing_events_tx,
                    incoming_events: incoming_events_rx,
                },
                ConnectionConfig {
                    log_tag: "test".into(),
                    post_request_interface_check_timeout,
                    transport_info: TransportInfo {
                        local_addr: (Ipv4Addr::LOCALHOST, 1000).into(),
                        remote_addr: (Ipv4Addr::LOCALHOST, 443).into(),
                    },
                    get_current_interface,
                },
                None,
                network_change_event,
                initial_request_id,
                listener,
                tokio::runtime::Handle::current(),
            );

            (chat, (outgoing_events_rx, incoming_events_tx))
        }

        #[pin_project(project = FakeInnerConnectionProj)]
        struct FakeInnerConnection<R> {
            #[pin]
            outgoing_tx: R,

            outgoing_events: Option<mpsc::UnboundedSender<OutgoingMessage>>,
            incoming_events: mpsc::UnboundedReceiver<
                OutcomeOrPanic<MessageEvent<OutgoingMeta>, Result<FinishReason, NextEventError>>,
            >,
        }

        #[derive(Debug)]
        pub(super) struct OutgoingMessage(pub TextOrBinary, pub OutgoingMeta);

        impl<R> InnerConnection for FakeInnerConnection<R>
        where
            R: FusedStream<Item = (TextOrBinary, OutgoingMeta)> + Send + 'static,
        {
            async fn handle_next_event(self: Pin<&mut Self>) -> WsEvent {
                let FakeInnerConnectionProj {
                    outgoing_events,
                    mut outgoing_tx,
                    incoming_events,
                } = self.project();

                loop {
                    enum Event<O, I> {
                        Outgoing(O),
                        Incoming(I),
                    }
                    let outgoing_tx_next = if outgoing_tx.is_terminated() {
                        Either::Right(std::future::pending())
                    } else {
                        Either::Left(outgoing_tx.next())
                    };
                    match select! {
                        outgoing = outgoing_tx_next => Event::Outgoing(outgoing),
                        incoming = incoming_events.recv() => Event::Incoming(incoming.expect("not hung up on")),
                    } {
                        Event::Outgoing(None) => {
                            log::debug!("client closed outgoing stream");
                            *outgoing_events = None;
                        }
                        Event::Outgoing(Some(outgoing)) => {
                            let (message, meta) = outgoing;
                            let outgoing_events =
                                outgoing_events.as_mut().expect("got event after close");
                            let _ignore_error =
                                outgoing_events.send(OutgoingMessage(message, meta));
                        }
                        Event::Incoming(incoming) => {
                            return match incoming {
                                OutcomeOrPanic::Continue(c) => Outcome::Continue(c),
                                OutcomeOrPanic::Finished(f) => Outcome::Finished(f),
                                OutcomeOrPanic::IntentionalPanic(message) => {
                                    panic!("intentional panic: {message}")
                                }
                            };
                        }
                    }
                }
            }
        }

        struct IntoFakeInnerConnection {
            outgoing_events: mpsc::UnboundedSender<OutgoingMessage>,
            incoming_events: mpsc::UnboundedReceiver<
                OutcomeOrPanic<MessageEvent<OutgoingMeta>, Result<FinishReason, NextEventError>>,
            >,
        }

        impl IntoInnerConnection for IntoFakeInnerConnection {
            fn into_inner_connection<R>(
                self,
                outgoing_stream: R,
                _log_tag: Arc<str>,
            ) -> impl InnerConnection + Send + 'static
            where
                R: Stream<Item = (TextOrBinary, OutgoingMeta)> + Send + 'static,
            {
                let Self {
                    outgoing_events,
                    incoming_events,
                } = self;
                FakeInnerConnection {
                    outgoing_tx: outgoing_stream.fuse(),
                    outgoing_events: Some(outgoing_events),
                    incoming_events,
                }
            }
        }
    }

    trait IntoEventListener {
        fn into_event_listener(self) -> EventListener;
    }

    impl IntoEventListener for mpsc::UnboundedSender<ListenerEvent> {
        fn into_event_listener(self) -> EventListener {
            Box::new(move |event| {
                let _ignore_failure = self.send(event);
            })
        }
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn sends_requests_and_receives_responses() {
        let (chat, (mut chat_events, inner_responses)) = fake::new_chat(Box::new(|_| ()));
        assert!(chat.is_connected().await);

        const REQUEST_PATHS: [&str; 3] = ["/first", "/second", "/third"];
        let request_headers = HeaderMap::from_iter([(
            "req-header".try_into().unwrap(),
            "value".try_into().unwrap(),
        )]);

        let mut send_requests = futures_util::stream::iter(REQUEST_PATHS)
            .map(|path| {
                chat.send(Request {
                    method: Method::GET,
                    path: PathAndQuery::from_static(path),
                    headers: request_headers.clone(),
                    body: None,
                })
            })
            .buffered(REQUEST_PATHS.len())
            .collect::<Vec<_>>();

        let receive_outbound_requests = async {
            let mut messages = Vec::with_capacity(REQUEST_PATHS.len());
            for _ in 0..messages.capacity() {
                let fake::OutgoingMessage(message, meta) =
                    chat_events.recv().await.expect("not ended");
                inner_responses
                    .send(Outcome::Continue(MessageEvent::SentMessage(meta)).into())
                    .expect("not closed");
                messages.push(message);
            }
            messages
        };

        // Start polling the client sending future and the server receive end.
        // The client sends won't finish until the responses to the requests are
        // received, so don't use `join!`. The server receive will complete,
        // though.
        let requests = select! {
            biased;
            responses = &mut send_requests => unreachable!("send finished before responses were sent: {responses:?}"),
            req = receive_outbound_requests => req,
        };

        let expected_reqs = REQUEST_PATHS
            .into_iter()
            .enumerate()
            .map(|(index, path)| RequestProto {
                id: Some(index as u64 + fake::INITIAL_REQUEST_ID),
                verb: Some("GET".to_string()),
                path: Some(path.to_string()),
                body: None,
                headers: vec!["req-header: value".to_string()],
            })
            .collect_vec();

        let expected_req_messages = expected_reqs
            .iter()
            .map(|request| {
                TextOrBinary::Binary(
                    MessageProto {
                        r#type: Some(ChatMessageType::Request.into()),
                        request: Some(request.clone()),
                        response: None,
                    }
                    .encode_to_vec()
                    .into(),
                )
            })
            .collect_vec();

        assert_eq!(requests, *expected_req_messages);

        let responses = expected_reqs
            .into_iter()
            .map(|request| ResponseProto {
                id: request.id,
                status: Some(200),
                message: None,
                headers: vec!["resp-header: value".to_string()],
                body: None,
            })
            .collect_vec();

        for response in &responses {
            inner_responses
                .send(
                    Outcome::Continue(MessageEvent::ReceivedMessage(TextOrBinary::Binary(
                        MessageProto::from(ChatMessageProto::Response(response.clone()))
                            .encode_to_vec()
                            .into(),
                    )))
                    .into(),
                )
                .expect("can send response")
        }

        let received_responses = send_requests.await;

        let expected_responses = responses
            .into_iter()
            .map(|proto| Ok(Response::try_from(proto).unwrap()))
            .collect_vec();
        assert_eq!(received_responses, expected_responses);
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn receives_incoming_server_requests_and_responds() {
        const INITIAL_INCOMING_REQUEST_ID: u64 = 88;

        let (received_events_tx, mut received_events_rx) = mpsc::unbounded_channel();

        let (_chat, (mut inner_events, inner_responses)) =
            fake::new_chat(received_events_tx.into_event_listener());

        const INCOMING_REQUEST_PATHS: [&str; 3] = ["/first", "/second", "/third"];

        let incoming_requests = INCOMING_REQUEST_PATHS
            .iter()
            .enumerate()
            .map(|(index, path)| RequestProto {
                id: Some(index as u64 + INITIAL_INCOMING_REQUEST_ID),
                verb: Some(Method::GET.to_string()),
                path: Some(path.to_string()),
                headers: vec!["req-header: value".to_string()],
                body: None,
            })
            .collect_vec();

        for request in &incoming_requests {
            inner_responses
                .send(
                    Outcome::Continue(MessageEvent::ReceivedMessage(TextOrBinary::Binary(
                        MessageProto {
                            r#type: Some(ChatMessageType::Request.into()),
                            request: Some(request.clone()),
                            response: None,
                        }
                        .encode_to_vec()
                        .into(),
                    )))
                    .into(),
                )
                .expect("can send requests from server");
        }

        // Because the task running in the background is continuing to run, it
        // should send events to the listener for the incoming requests and the
        // listener will bounce those to the channel.
        let received_events = [
            received_events_rx.recv().await,
            received_events_rx.recv().await,
            received_events_rx.recv().await,
        ]
        .map(|r| r.expect("received incoming event"));

        let raw_status_for_index = |index| 200 + u16::try_from(index).unwrap();

        // Validate the received events and send a response for each.
        for (index, event) in received_events.into_iter().enumerate() {
            let (proto, responder) = assert_matches!(event, ListenerEvent::ReceivedMessage(proto, responder) => (proto, responder));
            assert_eq!(proto, incoming_requests[index]);
            responder
                .send_response(StatusCode::from_u16(raw_status_for_index(index)).unwrap())
                .expect("can send response");
        }

        let expected_responses = incoming_requests
            .into_iter()
            .enumerate()
            .map(|(index, request)| {
                let status = raw_status_for_index(index);
                ResponseProto {
                    id: request.id,
                    status: Some(status.into()),
                    body: None,
                    headers: vec![],
                    message: Some(
                        StatusCode::from_u16(status)
                            .unwrap()
                            .canonical_reason()
                            .unwrap()
                            .to_string(),
                    ),
                }
            })
            .collect_vec();

        let expected_response_messages = expected_responses
            .iter()
            .map(|response| {
                MessageProto {
                    r#type: Some(ChatMessageType::Response.into()),
                    response: Some(response.clone()),
                    request: None,
                }
                .encode_to_vec()
            })
            .collect_vec();

        // The server side should receive those responses.
        let responses = [
            inner_events.recv().await,
            inner_events.recv().await,
            inner_events.recv().await,
        ]
        .map(|r| {
            assert_matches!(r.expect("can receive responses"),
            fake::OutgoingMessage(TextOrBinary::Binary(bytes), OutgoingMeta::ResponseToIncoming) => bytes)
        });

        assert_eq!(
            responses,
            *expected_response_messages,
            "decoded actual responses: {:?}",
            responses
                .iter()
                .map(|m| MessageProto::decode(&**m))
                .collect_vec()
        );
    }

    #[test_case(true; "server closed the stream")]
    #[test_case(false; "client called disconnect")]
    #[test_log::test(tokio::test(start_paused = true))]
    async fn send_error_if_server_disconnected_before_response(remote_initiated: bool) {
        let (received_events_tx, mut received_events_rx) = mpsc::unbounded_channel();
        let (chat, (mut inner_events, inner_responses)) =
            fake::new_chat(received_events_tx.into_event_listener());

        inner_responses
            .send(
                Outcome::Continue(MessageEvent::ReceivedMessage(TextOrBinary::Binary(
                    MessageProto::from(ChatMessageProto::Request(RequestProto {
                        id: Some(8675309),
                        verb: Some(Method::DELETE.to_string()),
                        body: None,
                        headers: vec![],
                        path: Some("/".to_string()),
                    }))
                    .encode_to_vec()
                    .into(),
                )))
                .into(),
            )
            .expect("client is listening");

        let event = received_events_rx.recv().await.expect("incoming event");
        let responder =
            assert_matches!(event, ListenerEvent::ReceivedMessage(_proto, responder) => responder);

        if !remote_initiated {
            // Start the client-initiated disconnect. This won't shut down the
            // task since it will be waiting for the inner connection to respond
            // with `Outcome::Finished`.
            chat.disconnect().await;
        }
        // Signal the task to exit. This is either "successfully sent a Close
        // frame after the client requested a disconnect" or "the server sent a
        // Close frame unprompted". Either way, the task should exit and hang up
        // on the event stream.
        let finish_reason = if remote_initiated {
            FinishReason::RemoteDisconnect
        } else {
            FinishReason::LocalDisconnect
        };
        inner_responses
            .send(Outcome::Finished(Ok(finish_reason)).into())
            .expect("not hung up on");

        assert_matches!(inner_events.recv().await, None);
        assert_matches!(
            received_events_rx.recv().await,
            Some(ListenerEvent::Finished(Ok(reason))) if reason == finish_reason
        );
        assert_matches!(
            responder.send_response(StatusCode::OK),
            Err(SendError::Disconnected { .. })
        );
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn request_succeeds_even_if_followed_immediately_by_close() {
        let (chat, (mut chat_events, inner_responses)) = fake::new_chat(Box::new(|_| ()));
        assert!(chat.is_connected().await);

        let request = Request {
            method: Method::GET,
            path: PathAndQuery::from_static("/request"),
            headers: HeaderMap::default(),
            body: None,
        };
        let mut send_request = std::pin::pin!(chat.send(request));

        let receive_outbound_request = async {
            let fake::OutgoingMessage(_message, meta) =
                chat_events.recv().await.expect("not ended");
            let request_id = assert_matches!(&meta, OutgoingMeta::SentRequest(id, _) => *id);
            inner_responses
                .send(Outcome::Continue(MessageEvent::SentMessage(meta)).into())
                .expect("not closed");
            request_id
        };

        // Start polling the client sending future and the server receive end.
        // The client sends won't finish until the response to the request is
        // received, so do't use `join!`. The server receive will complete,
        // though.
        let sent_request_id = select! {
            biased;
            response = &mut send_request => unreachable!("send finished before responses were sent: {response:?}"),
            req = receive_outbound_request => req,
        };

        let response = ResponseProto {
            id: Some(sent_request_id.0),
            status: Some(200),
            message: None,
            headers: vec!["resp-header: value".to_string()],
            body: None,
        };

        // Send the response, then immediately send a "finished" event.
        for outcome in [
            Outcome::Continue(MessageEvent::ReceivedMessage(TextOrBinary::Binary(
                MessageProto::from(ChatMessageProto::Response(response))
                    .encode_to_vec()
                    .into(),
            ))),
            Outcome::Finished(Ok(FinishReason::RemoteDisconnect)),
        ] {
            inner_responses
                .send(outcome.into())
                .expect("can send response");
        }

        let _response = send_request.await.expect("request succeeded");
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn disconnects_server_on_client_disconnect() {
        let (chat, (mut inner_events, _inner_responses)) = fake::new_chat(Box::new(|_| ()));

        chat.disconnect().await;
        assert!(!chat.is_connected().await);

        // The client should send a disconnect to the server.
        assert_matches!(inner_events.recv().await, None);

        // Future sends should fail!
        let failed_send = chat
            .send(Request {
                method: Method::GET,
                body: None,
                headers: Default::default(),
                path: PathAndQuery::from_static("/"),
            })
            .await;
        assert_matches!(failed_send, Err(SendError::Disconnected { .. }));
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn client_disconnect_twice() {
        let (chat, (_inner_events, _inner_responses)) = fake::new_chat(Box::new(|_| ()));

        chat.disconnect().await;
        chat.disconnect().await;
    }

    #[test_case(true; "outgoing request")]
    #[test_case(false; "response to incoming request")]
    #[test_log::test(tokio::test(start_paused = true))]
    async fn send_failure_causes_disconnect(outgoing_request_fails: bool) {
        let (received_events_tx, mut received_events_rx) = mpsc::unbounded_channel();
        let listener = if outgoing_request_fails {
            Box::new(|_| ()) as EventListener
        } else {
            Box::new(move |event| {
                let _ignore_send_failure = received_events_tx.send(event);
            })
        };
        let (chat, (mut chat_events, inner_responses)) = fake::new_chat(listener);

        let send_future = if outgoing_request_fails {
            let send = chat.send(Request {
                method: Method::GET,
                path: PathAndQuery::from_static("/"),
                headers: HeaderMap::default(),
                body: None,
            });
            Some(send)
        } else {
            // Send an incoming request and send a response to it.

            inner_responses
                .send(
                    Outcome::Continue(MessageEvent::ReceivedMessage(TextOrBinary::Binary(
                        MessageProto::from(ChatMessageProto::Request(RequestProto {
                            id: Some(123),
                            ..Default::default()
                        }))
                        .encode_to_vec()
                        .into(),
                    )))
                    .into(),
                )
                .expect("not disconnected");
            let event = received_events_rx.recv().await.expect("incoming event");
            let responder = assert_matches!(event, ListenerEvent::ReceivedMessage(_proto, responder) => responder);
            responder
                .send_response(StatusCode::CONTINUE)
                .expect("not disconnected");

            None
        };

        let mut send_future = std::pin::pin!(send_future);

        if let Some(send_future) = send_future.as_mut().as_pin_mut() {
            // Kick off the actual outgoing message, even though the send won't complete.
            assert_matches!(futures_util::poll!(send_future), std::task::Poll::Pending);
        }
        let fake::OutgoingMessage(_message, meta) = chat_events.recv().await.expect("not ended");

        // Fail the send.
        inner_responses
            .send(
                Outcome::Continue(MessageEvent::SendFailed(
                    meta,
                    TungsteniteSendError::Io(IoError::new(
                        IoErrorKind::ConnectionReset,
                        "it broke!",
                    )),
                ))
                .into(),
            )
            .expect("not closed");

        if let Some(send_future) = send_future.as_pin_mut() {
            // The client request should now be able to finish.
            assert_matches!(
                send_future.await,
                Err(SendError::Io(IoErrorKind::ConnectionReset))
            );
        }

        // After a failed send, the service gets disconnected.
        assert_matches!(chat_events.recv().await, None);
        assert!(!chat.is_connected().await);
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn sends_listener_close_on_remote_disconnect() {
        let (received_events_tx, mut received_events_rx) = mpsc::unbounded_channel();

        let (_chat, (_inner_events, inner_responses)) =
            fake::new_chat(received_events_tx.into_event_listener());

        inner_responses
            .send(Outcome::Finished(Ok(FinishReason::RemoteDisconnect)).into())
            .expect("can send");
        assert_matches!(
            received_events_rx.recv().await,
            Some(ListenerEvent::Finished(Ok(FinishReason::RemoteDisconnect)))
        );
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn is_not_connected_after_remote_close() {
        let (received_close_tx, mut received_close_rx) = mpsc::unbounded_channel();
        let (chat, (_inner_events, inner_responses)) = fake::new_chat(Box::new(move |e| {
            if let ListenerEvent::Finished(_) = e {
                let _ignore_error = received_close_tx.send(());
            }
        }));

        inner_responses
            .send(Outcome::Finished(Ok(FinishReason::RemoteDisconnect)).into())
            .expect("can send");

        received_close_rx.recv().await;
        // Wait for some amount of simulated time to elapse. Since the Chat's
        // background task isn't just waiting for time to elapse it will
        // receive the incoming message and terminate the connection.
        tokio::time::sleep(Duration::from_millis(1)).await;

        assert!(!chat.is_connected().await);
    }

    #[test_case(
        CloseCode::from(CONNECTION_INVALIDATED_CLOSE_CODE) => matches crate::chat::SendError::ConnectionInvalidated;
        "CONNECTION_INVALIDATED_CLOSE_CODE results in ConnectionInvalidated"
    )]
    #[test_case(
        CloseCode::from(CONNECTED_ELSEWHERE_CLOSE_CODE) => matches crate::chat::SendError::ConnectedElsewhere;
        "CONNECTED_ELSEWHERE_CLOSE_CODE results in ConnectedElsewhere"
    )]
    #[test_case(
        CloseCode::Normal => matches crate::chat::SendError::WebSocket(WebSocketError::ChannelClosed);
        "Normal close results in WebSocket ChannelClosed"
    )]
    #[test_case(
        CloseCode::from(4499_u16) => matches crate::chat::SendError::WebSocket(WebSocketError::ChannelClosed);
        "Other abnormal close results in WebSocket ChannelClosed"
    )]
    #[test_log::test(tokio::test(start_paused = true))]
    async fn websocket_close_code_maps_to_correct_error(
        close_code: CloseCode,
    ) -> crate::chat::SendError {
        let (received_events_tx, mut received_events_rx) = mpsc::unbounded_channel();
        let (chat, (_inner_events, inner_responses)) =
            fake::new_chat(received_events_tx.into_event_listener());
        assert!(chat.is_connected().await);

        inner_responses
            .send(
                Outcome::Finished(Err(NextEventError::AbnormalServerClose {
                    code: close_code,
                    reason: format!("close code: {close_code}"),
                }))
                .into(),
            )
            .expect("can disconnect");

        let listener_event = received_events_rx
            .recv()
            .await
            .expect("should receive an event");

        // Extract the TaskExitError from the listener event
        let task_exit_error = match listener_event {
            ListenerEvent::Finished(Err(FinishError::Error(
                task_exit_error @ TaskExitError::WebsocketError(
                    NextEventError::AbnormalServerClose { code, reason: _ },
                ),
            ))) => {
                assert_eq!(code, close_code);
                task_exit_error
            }
            other => panic!("Unexpected listener event: {other:?}"),
        };

        // Convert the TaskExitError to a SendError, which is closest to what is eventually passed up to
        //   the clients across the bridge.
        let actual_error: crate::chat::SendError = task_exit_error.into();
        actual_error
    }

    impl From<MessageProto> for TextOrBinary {
        fn from(proto: MessageProto) -> Self {
            TextOrBinary::Binary(proto.encode_to_vec().into())
        }
    }

    #[test_case(MessageProto::default(); "empty message")]
    #[test_case(MessageProto::from(ChatMessageProto::Response(ResponseProto {
                    id: Some(123),
                    ..Default::default()
                })); "unknown request ID")]
    #[test_case(MessageProto {
                    r#type: Some(ChatMessageType::Request.into()),
                    response: Some(Default::default()),
                    request: None,
                }; "invalid request")]
    #[test_case("unexpected"; "text frame")]
    #[test_case(Vec::from(b"not a proto"); "invalid proto")]
    #[test_log::test(tokio::test(start_paused = true))]
    async fn continues_on_invalid_incoming_message(incoming: impl Into<TextOrBinary>) {
        let (received_events_tx, mut received_events_rx) = mpsc::unbounded_channel();

        let (_chat, (_inner_events, inner_responses)) =
            fake::new_chat(received_events_tx.into_event_listener());

        // Send 2 incoming requests. Since they are processed in order, if the
        // second one comes in we know the first one didn't cause the worker to
        // exit.
        let second_request = RequestProto {
            id: Some(555),
            verb: Some(Method::GET.to_string()),
            path: Some("/".to_string()),
            headers: vec![],
            body: None,
        };
        let messages = [
            incoming.into(),
            MessageProto::from(ChatMessageProto::Request(second_request.clone())).into(),
        ];

        for m in messages {
            inner_responses
                .send(Outcome::Continue(MessageEvent::ReceivedMessage(m)).into())
                .expect("not hung up on");
        }

        let next = received_events_rx.recv().await;
        let (proto, _responder) = assert_matches!(next, Some(ListenerEvent::ReceivedMessage(proto, responder)) => (proto, responder));
        assert_eq!(proto, second_request);
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn request_id_wraps_around() {
        let (chat, (mut inner_events, inner_responses)) = fake::new_chat_with_config(
            fake::FakeConfig {
                initial_request_id: u64::MAX,
                ..Default::default()
            },
            |_| std::future::ready(Ipv4Addr::LOCALHOST.into()),
            Box::new(|_| ()),
        );

        let mut send_requests = FuturesUnordered::from_iter(["/a", "/b"].map(|path| {
            chat.send(Request {
                method: Method::GET,
                path: PathAndQuery::from_static(path),
                headers: Default::default(),
                body: None,
            })
        }));

        let receive_outbound_requests = async {
            let mut messages = Vec::with_capacity(2);
            for _ in 0..messages.capacity() {
                let fake::OutgoingMessage(message, meta) =
                    inner_events.recv().await.expect("not ended");
                inner_responses
                    .send(Outcome::Continue(MessageEvent::SentMessage(meta)).into())
                    .expect("not closed");
                let msg = assert_matches!(message, TextOrBinary::Binary(msg) => msg);
                messages.push(MessageProto::decode(&*msg).expect("valid proto"))
            }
            messages
        };

        let sent_messages = tokio::select! {
            biased;
            _ = send_requests.next() => unreachable!("sends don't complete until responses are received"),
            outgoing = receive_outbound_requests => outgoing
        };

        assert_matches!(
            &*sent_messages,
            [
                MessageProto {
                    request: Some(RequestProto {
                        id: Some(u64::MAX),
                        ..
                    }),
                    ..
                },
                MessageProto {
                    request: Some(RequestProto { id: Some(0), .. }),
                    ..
                }
            ]
        )
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn listener_panic_on_receive_incoming() {
        let (listener_tx, mut listener_rx) = mpsc::unbounded_channel();

        let (_chat, (_inner_events, inner_responses)) = fake::new_chat(Box::new(move |event| {
            listener_tx.send(()).expect("listener exists");
            if let ListenerEvent::ReceivedMessage(req, _responder) = event {
                panic!("expected panic on receiving {req:?}");
            }
        }));

        inner_responses
            .send(
                Outcome::Continue(MessageEvent::ReceivedMessage(TextOrBinary::Binary(
                    MessageProto::from(ChatMessageProto::Request(RequestProto {
                        id: Some(123),
                        ..Default::default()
                    }))
                    .encode_to_vec()
                    .into(),
                )))
                .into(),
            )
            .unwrap();

        // The listener should send the one item and then drop the sender.
        assert_matches!(listener_rx.recv().await, Some(()));
        assert_matches!(listener_rx.recv().await, None);
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn listener_panic_during_task_panic_doesnt_abort() {
        let (listener_tx, mut listener_rx) = mpsc::unbounded_channel();

        let (_chat, (_inner_events, inner_responses)) = fake::new_chat(Box::new(move |event| {
            listener_tx
                .send(matches!(
                    event,
                    ListenerEvent::Finished(Err(FinishError::Unknown))
                ))
                .expect("can send");
            panic!("expected panic on receiving {event:?}");
        }));

        inner_responses
            .send(fake::OutcomeOrPanic::IntentionalPanic("oh noes!"))
            .expect("not dead yet");

        assert_eq!(listener_rx.recv().await, Some(true));
        assert_matches!(listener_rx.recv().await, None);
    }

    #[test]
    fn reports_alerts() {
        let (listener_tx, mut listener_rx) = mpsc::unbounded_channel();
        let mut listener_tx: EventListener =
            Box::new(move |evt| listener_tx.send(evt).expect("can send"));

        Chat::report_alerts(http::HeaderMap::default(), &mut listener_tx);
        assert_matches!(
            listener_rx.try_recv().expect("present"),
            ListenerEvent::ReceivedAlerts(alerts) if alerts.is_empty()
        );
        assert_matches!(listener_rx.try_recv(), Err(TryRecvError::Empty));

        Chat::report_alerts(
            http::HeaderMap::from_iter(
                [
                    ("unrelated", "other"),
                    (ALERT_HEADER_NAME, "first"),
                    ("yet-another", "something"),
                    (ALERT_HEADER_NAME, "second,third, fourth"),
                    ("last-one", "x"),
                ]
                .map(|(name, val)| {
                    (
                        http::HeaderName::from_static(name),
                        http::HeaderValue::from_static(val),
                    )
                }),
            ),
            &mut listener_tx,
        );

        assert_matches!(
            listener_rx.try_recv().expect("present"),
            ListenerEvent::ReceivedAlerts(alerts) if alerts == ["first", "second", "third", "fourth"]
        );
        assert_matches!(listener_rx.try_recv(), Err(TryRecvError::Empty));
    }

    #[test_case(
        CloseCode::from(CONNECTION_INVALIDATED_CLOSE_CODE), SendError::Disconnected(DisconnectedReason::ConnectionInvalidated);
        "CONNECTION_INVALIDATED_CLOSE_CODE results in ConnectionInvalidated"
    )]
    #[test_case(
        CloseCode::from(CONNECTED_ELSEWHERE_CLOSE_CODE), SendError::Disconnected(DisconnectedReason::ConnectedElsewhere);
        "CONNECTED_ELSEWHERE_CLOSE_CODE results in ConnectedElsewhere"
    )]
    #[test_case(
        CloseCode::Normal, SendError::Disconnected(DisconnectedReason::SocketClosed { #[cfg(test)] reason: "server closed abnormally" });
        "Normal close results in Disconnected"
    )]
    #[test_log::test(tokio::test(start_paused = true))]
    async fn send_after_ws_close_returns_proper_error(
        close_code: CloseCode,
        expected_error: SendError,
    ) {
        let (chat, (_inner_events, inner_responses)) = fake::new_chat(Box::new(|_| ()));
        assert!(chat.is_connected().await);

        // Close the connection with the specific close code
        inner_responses
            .send(
                Outcome::Finished(Err(NextEventError::AbnormalServerClose {
                    code: close_code,
                    reason: format!("close code: {close_code}"),
                }))
                .into(),
            )
            .expect("can send close event");

        let wait_for_disconnect = async {
            while chat.is_connected().await {
                tokio::task::yield_now().await;
            }
        };

        tokio::time::timeout(Duration::from_secs(1), wait_for_disconnect)
            .await
            .expect("chat disconnect does not take long");

        // Try to send a request, which should fail with the expected error
        let send_result = chat
            .send(Request {
                method: Method::GET,
                path: PathAndQuery::from_static("/test"),
                headers: HeaderMap::default(),
                body: None,
            })
            .await;

        assert_eq!(send_result, Err(expected_error));
    }

    #[test_case(
        CloseCode::from(CONNECTION_INVALIDATED_CLOSE_CODE),
        SendError::Disconnected(DisconnectedReason::ConnectionInvalidated);
        "CONNECTION_INVALIDATED_CLOSE_CODE should propagate correctly"
    )]
    #[test_case(
        CloseCode::from(CONNECTED_ELSEWHERE_CLOSE_CODE),
        SendError::Disconnected(DisconnectedReason::ConnectedElsewhere);
        "CONNECTED_ELSEWHERE_CLOSE_CODE should propagate correctly"
    )]
    #[test_case(
        CloseCode::Normal,
        SendError::Disconnected(DisconnectedReason::SocketClosed { #[cfg(test)] reason: "server closed abnormally" });
        "Normal close results in Disconnected"
    )]
    #[test_log::test(tokio::test(start_paused = true))]
    async fn connection_close_with_in_flight_request(
        close_code: CloseCode,
        expected_error: SendError,
    ) {
        // Create channels for listener events
        let (listener_tx, mut listener_rx) = mpsc::unbounded_channel();
        let (chat, (mut chat_events, inner_responses)) = fake::new_chat(Box::new(move |evt| {
            let _ = listener_tx.send(evt);
        }));

        // Start a request but don't complete it right away
        let send_task = tokio::spawn(async move {
            chat.send(Request {
                method: Method::GET,
                path: PathAndQuery::from_static("/test"),
                headers: HeaderMap::default(),
                body: None,
            })
            .await
        });

        // Take the outbound message and acknowledge it was sent
        if let Some(fake::OutgoingMessage(_, meta)) = chat_events.recv().await {
            inner_responses
                .send(Outcome::Continue(MessageEvent::SentMessage(meta)).into())
                .expect("Should be able to send event");
        } else {
            panic!("Failed to receive outbound message");
        }

        // Now close the connection with the specified close code
        inner_responses
            .send(
                Outcome::Finished(Err(NextEventError::AbnormalServerClose {
                    code: close_code,
                    reason: format!("Test close with code: {close_code}"),
                }))
                .into(),
            )
            .expect("Should be able to send close event");

        // Wait for the listener to receive the close event
        let mut received_close = false;
        while let Some(event) = listener_rx.recv().await {
            if let ListenerEvent::Finished(_) = event {
                received_close = true;
                break;
            }
        }
        assert!(
            received_close,
            "Listener should have received a close event"
        );

        // Wait for the send task to complete and verify the error type
        let send_result = tokio::time::timeout(Duration::from_secs(1), send_task)
            .await
            .expect("send completes within timeout")
            .expect("Task should not panic");

        assert_eq!(send_result, Err(expected_error));
    }

    fn stream_of_events_other_than_responses() -> impl Stream<Item = WsEvent> {
        let seed = std::env::var("LIBSIGNAL_TESTING_SEED")
            .map(|seed| seed.parse().expect("valid integer"))
            .unwrap_or_else(|_| rand::random());
        log::info!("LIBSIGNAL_TESTING_SEED={seed}");

        // These are functions because MessageEvent isn't Clone.
        let items = [
            || MessageEvent::SentPing,
            || MessageEvent::ReceivedPingPong,
            || MessageEvent::ReceivedMessage(TextOrBinary::Binary(vec![].into())),
            || MessageEvent::SentMessage(OutgoingMeta::ResponseToIncoming),
        ];
        let mut next_event = Instant::now();
        let mut rng1 = rand_chacha::ChaCha8Rng::seed_from_u64(seed);
        let mut rng2 = rng1.clone();
        futures_util::stream::repeat_with(move || {
            next_event += Duration::from_millis(100 * rng1.random_range(0..20));
            next_event
        })
        .then(tokio::time::sleep_until)
        .map(move |_| {
            let item = items.choose(&mut rng2).expect("non-empty")();
            log::debug!("injecting {item:?}");
            Outcome::Continue(item)
        })
    }

    async fn expect_connection_closed(
        expected_elapsed: Duration,
        mut listener_rx: mpsc::UnboundedReceiver<ListenerEvent>,
        (mut chat_events, inner_responses): fake::FakeTxRxChannels,
        other_events: impl Stream<Item = WsEvent>,
    ) {
        let start = Instant::now();
        let mut other_events = std::pin::pin!(other_events.fuse());

        // Let the "server" process the end of the request stream,
        // and then the client can receive the Finished event.
        let mut received_close = false;
        loop {
            tokio::task::yield_now().await;
            let event = select! {
                biased;
                event = listener_rx.recv() => event,
                event = chat_events.recv() => {
                    assert!(event.is_none(), "no further outgoing messages expected");
                    inner_responses
                        .send(Outcome::Finished(Ok(FinishReason::LocalDisconnect)).into())
                        .expect("not hung up on");
                    continue;
                }
                extra_ws_event = other_events.next(),
                if !other_events.is_terminated() && !received_close => {
                    if let Some(event) = extra_ws_event {
                        inner_responses.send(event.into()).expect("not hung up on");
                    }
                    continue;
                }
            };
            let Some(event) = event else {
                break;
            };
            received_close = matches!(event, ListenerEvent::Finished(_));
        }

        assert!(
            received_close,
            "Listener should have received a close event"
        );
        assert_eq!(start.elapsed(), expected_elapsed);
    }

    async fn expect_connection_not_closed(
        time_to_wait: Duration,
        mut listener_rx: mpsc::UnboundedReceiver<ListenerEvent>,
        (mut chat_events, inner_responses): fake::FakeTxRxChannels,
        other_events: impl Stream<Item = WsEvent>,
    ) {
        let mut deadline = std::pin::pin!(tokio::time::sleep(time_to_wait));
        let mut other_events = std::pin::pin!(other_events.fuse());

        // Let the "server" process the end of the request stream,
        // and then the client can receive the Finished event.
        loop {
            tokio::task::yield_now().await;
            let event = select! {
                biased;
                event = listener_rx.recv() => event,
                event = chat_events.recv() => {
                    if event.is_some() {
                        panic!("no additional outgoing messages should be sent");
                    } else {
                        panic!("the connection should not be closed");
                    }
                }
                extra_ws_event = other_events.next(), if !other_events.is_terminated() => {
                    if let Some(event) = extra_ws_event {
                        inner_responses.send(event.into()).expect("not hung up on");
                    }
                    continue;
                }
                _ = &mut deadline => {
                    break;
                }
            };
            let event = event.expect("should not have closed yet");
            assert_matches!(
                event,
                ListenerEvent::ReceivedMessage { .. },
                "should not have Finished"
            );
        }

        // We reached the deadline without a post-request timeout, as expected.
    }

    #[test_case(futures_util::stream::empty())]
    #[test_case(stream_of_events_other_than_responses())]
    #[test_log::test(tokio::test(start_paused = true))]
    async fn connection_close_if_no_response_for_x_seconds(
        other_events: impl Stream<Item = WsEvent>,
    ) {
        // Create channels for listener events
        let (listener_tx, listener_rx) = mpsc::unbounded_channel();
        let (chat, (mut chat_events, inner_responses)) = fake::new_chat_with_config(
            Default::default(),
            |_| {
                // Behave as if we've switched interfaces immediately after connecting.
                std::future::ready(ip_addr!("192.168.0.1"))
            },
            Box::new(move |evt| {
                let _ = listener_tx.send(evt);
            }),
        );

        assert!(chat.is_connected().await);

        let request = Request {
            method: Method::GET,
            path: PathAndQuery::from_static("/request"),
            headers: HeaderMap::default(),
            body: None,
        };
        let mut send_request = std::pin::pin!(chat.send(request));

        let receive_outbound_request = async {
            let fake::OutgoingMessage(_message, meta) =
                chat_events.recv().await.expect("not ended");
            let request_id = assert_matches!(&meta, OutgoingMeta::SentRequest(id, _) => *id);
            inner_responses
                .send(Outcome::Continue(MessageEvent::SentMessage(meta)).into())
                .expect("not closed");
            request_id
        };

        // Start polling the client sending future and the server receive end.
        // The client sends won't finish until the response to the request is
        // received, so do't use `join!`. The server receive will complete,
        // though.
        let _sent_request_id = select! {
            biased;
            response = &mut send_request => unreachable!("send finished before responses were sent: {response:?}"),
            req = receive_outbound_request => req,
        };

        expect_connection_closed(
            fake::POST_REQUEST_TIMEOUT,
            listener_rx,
            (chat_events, inner_responses),
            other_events,
        )
        .await;
    }

    #[test_case(futures_util::stream::empty())]
    #[test_case(stream_of_events_other_than_responses())]
    #[test_log::test(tokio::test(start_paused = true))]
    async fn connection_close_if_no_response_for_x_seconds_handles_max_timeout(
        other_events: impl Stream<Item = WsEvent>,
    ) {
        // Create channels for listener events
        let (listener_tx, listener_rx) = mpsc::unbounded_channel();
        let (chat, (mut chat_events, inner_responses)) = fake::new_chat_with_config(
            fake::FakeConfig {
                post_request_interface_check_timeout: Duration::MAX,
                ..Default::default()
            },
            |_| {
                // Behave as if we've switched interfaces immediately after connecting.
                std::future::ready(ip_addr!("192.168.0.1"))
            },
            Box::new(move |evt| {
                let _ = listener_tx.send(evt);
            }),
        );

        assert!(chat.is_connected().await);

        let request = Request {
            method: Method::GET,
            path: PathAndQuery::from_static("/request"),
            headers: HeaderMap::default(),
            body: None,
        };
        let mut send_request = std::pin::pin!(chat.send(request));

        let receive_outbound_request = async {
            let fake::OutgoingMessage(_message, meta) =
                chat_events.recv().await.expect("not ended");
            let request_id = assert_matches!(&meta, OutgoingMeta::SentRequest(id, _) => *id);
            inner_responses
                .send(Outcome::Continue(MessageEvent::SentMessage(meta)).into())
                .expect("not closed");
            request_id
        };

        // Start polling the client sending future and the server receive end.
        // The client sends won't finish until the response to the request is
        // received, so do't use `join!`. The server receive will complete,
        // though.
        let _sent_request_id = select! {
            biased;
            response = &mut send_request => unreachable!("send finished before responses were sent: {response:?}"),
            req = receive_outbound_request => req,
        };

        expect_connection_not_closed(
            10 * fake::POST_REQUEST_TIMEOUT,
            listener_rx,
            (chat_events, inner_responses),
            other_events,
        )
        .await;
    }

    #[test_case(futures_util::stream::empty())]
    #[test_case(stream_of_events_other_than_responses())]
    #[test_log::test(tokio::test(start_paused = true))]
    async fn connection_close_if_no_response_for_x_seconds_only_if_interface_actually_changed(
        other_events: impl Stream<Item = WsEvent>,
    ) {
        // Create channels for listener events
        let (listener_tx, listener_rx) = mpsc::unbounded_channel();
        let (chat, (mut chat_events, inner_responses)) = fake::new_chat_with_config(
            Default::default(),
            |_| {
                // If we didn't switch interfaces, we shouldn't close the connection.
                std::future::ready(Ipv4Addr::LOCALHOST.into())
            },
            Box::new(move |evt| {
                let _ = listener_tx.send(evt);
            }),
        );

        assert!(chat.is_connected().await);

        let request = Request {
            method: Method::GET,
            path: PathAndQuery::from_static("/request"),
            headers: HeaderMap::default(),
            body: None,
        };
        let mut send_request = std::pin::pin!(chat.send(request));

        let receive_outbound_request = async {
            let fake::OutgoingMessage(_message, meta) =
                chat_events.recv().await.expect("not ended");
            let request_id = assert_matches!(&meta, OutgoingMeta::SentRequest(id, _) => *id);
            inner_responses
                .send(Outcome::Continue(MessageEvent::SentMessage(meta)).into())
                .expect("not closed");
            request_id
        };

        // Start polling the client sending future and the server receive end.
        // The client sends won't finish until the response to the request is
        // received, so do't use `join!`. The server receive will complete,
        // though.
        let _sent_request_id = select! {
            biased;
            response = &mut send_request => unreachable!("send finished before responses were sent: {response:?}"),
            req = receive_outbound_request => req,
        };

        expect_connection_not_closed(
            10 * fake::POST_REQUEST_TIMEOUT,
            listener_rx,
            (chat_events, inner_responses),
            other_events,
        )
        .await;
    }

    #[test_case(futures_util::stream::empty())]
    #[test_case(stream_of_events_other_than_responses())]
    #[test_log::test(tokio::test(start_paused = true))]
    async fn connection_close_if_no_response_for_x_seconds_only_does_one_check_per_x_seconds(
        other_events: impl Stream<Item = WsEvent>,
    ) {
        let start = Instant::now();

        // Create channels for listener events
        let (listener_tx, listener_rx) = mpsc::unbounded_channel();
        let (chat, (mut chat_events, inner_responses)) = fake::new_chat_with_config(
            Default::default(),
            move |_| {
                std::future::ready(
                    if start.elapsed() < fake::POST_REQUEST_TIMEOUT.mul_f32(1.5) {
                        Ipv4Addr::LOCALHOST.into()
                    } else {
                        ip_addr!("192.168.0.1")
                    },
                )
            },
            Box::new(move |evt| {
                let _ = listener_tx.send(evt);
            }),
        );

        assert!(chat.is_connected().await);

        let request = Request {
            method: Method::GET,
            path: PathAndQuery::from_static("/request"),
            headers: HeaderMap::default(),
            body: None,
        };
        let mut send_request = std::pin::pin!(chat.send(request));

        let receive_outbound_request = async {
            let fake::OutgoingMessage(_message, meta) =
                chat_events.recv().await.expect("not ended");
            let request_id = assert_matches!(&meta, OutgoingMeta::SentRequest(id, _) => *id);
            inner_responses
                .send(Outcome::Continue(MessageEvent::SentMessage(meta)).into())
                .expect("not closed");
            request_id
        };

        // Start polling the client sending future and the server receive end.
        // The client sends won't finish until the response to the request is
        // received, so do't use `join!`. The server receive will complete,
        // though.
        let _sent_request_id = select! {
            biased;
            response = &mut send_request => unreachable!("send finished before responses were sent: {response:?}"),
            req = receive_outbound_request => req,
        };

        expect_connection_closed(
            2 * fake::POST_REQUEST_TIMEOUT,
            listener_rx,
            (chat_events, inner_responses),
            other_events,
        )
        .await;
    }

    #[test_case(futures_util::stream::empty())]
    #[test_case(stream_of_events_other_than_responses())]
    #[test_log::test(tokio::test(start_paused = true))]
    async fn connection_close_if_no_response_for_x_seconds_only_waits_for_first_in_set(
        other_events: impl Stream<Item = WsEvent>,
    ) {
        // Create channels for listener events
        let (listener_tx, listener_rx) = mpsc::unbounded_channel();
        let (chat, (mut chat_events, inner_responses)) = fake::new_chat_with_config(
            Default::default(),
            |_| {
                // Behave as if we've switched interfaces immediately after connecting.
                std::future::ready(ip_addr!("192.168.0.1"))
            },
            Box::new(move |evt| {
                let _ = listener_tx.send(evt);
            }),
        );

        assert!(chat.is_connected().await);

        let mut send_requests = FuturesUnordered::from_iter(["/a", "/b"].map(|path| {
            chat.send(Request {
                method: Method::GET,
                path: PathAndQuery::from_static(path),
                headers: Default::default(),
                body: None,
            })
        }));

        let receive_outbound_requests = async {
            let mut messages = Vec::with_capacity(2);
            for _ in 0..messages.capacity() {
                let fake::OutgoingMessage(message, meta) =
                    chat_events.recv().await.expect("not ended");
                inner_responses
                    .send(Outcome::Continue(MessageEvent::SentMessage(meta)).into())
                    .expect("not closed");
                let msg = assert_matches!(message, TextOrBinary::Binary(msg) => msg);
                messages.push(MessageProto::decode(&*msg).expect("valid proto"))
            }
            messages
        };

        let sent_messages = tokio::select! {
            biased;
            _ = send_requests.next() => unreachable!("sends don't complete until responses are received"),
            outgoing = receive_outbound_requests => outgoing
        };

        // Respond to the first one promptly.
        let response = ResponseProto {
            id: sent_messages[0].request.as_ref().expect("is request").id,
            status: Some(200),
            message: None,
            headers: vec!["resp-header: value".to_string()],
            body: None,
        };
        inner_responses
            .send(
                Outcome::Continue(MessageEvent::ReceivedMessage(TextOrBinary::Binary(
                    MessageProto::from(ChatMessageProto::Response(response))
                        .encode_to_vec()
                        .into(),
                )))
                .into(),
            )
            .expect("can send response");

        expect_connection_not_closed(
            10 * fake::POST_REQUEST_TIMEOUT,
            listener_rx,
            (chat_events, inner_responses),
            other_events,
        )
        .await;
    }

    #[test_case(futures_util::stream::empty())]
    #[test_case(stream_of_events_other_than_responses())]
    #[test_log::test(tokio::test(start_paused = true))]
    async fn connection_close_if_no_response_for_x_seconds_only_checks_first_in_set(
        other_events: impl Stream<Item = WsEvent>,
    ) {
        // Create channels for listener events
        let (listener_tx, listener_rx) = mpsc::unbounded_channel();
        let (chat, (mut chat_events, inner_responses)) = fake::new_chat_with_config(
            Default::default(),
            |_| {
                // Behave as if we've switched interfaces immediately after connecting.
                std::future::ready(ip_addr!("192.168.0.1"))
            },
            Box::new(move |evt| {
                let _ = listener_tx.send(evt);
            }),
        );

        assert!(chat.is_connected().await);

        let mut send_requests = FuturesUnordered::from_iter(["/a", "/b"].map(|path| {
            chat.send(Request {
                method: Method::GET,
                path: PathAndQuery::from_static(path),
                headers: Default::default(),
                body: None,
            })
        }));

        let receive_outbound_requests = async {
            let mut messages = Vec::with_capacity(2);
            for _ in 0..messages.capacity() {
                let fake::OutgoingMessage(message, meta) =
                    chat_events.recv().await.expect("not ended");
                inner_responses
                    .send(Outcome::Continue(MessageEvent::SentMessage(meta)).into())
                    .expect("not closed");
                let msg = assert_matches!(message, TextOrBinary::Binary(msg) => msg);
                messages.push(MessageProto::decode(&*msg).expect("valid proto"))
            }
            messages
        };

        let sent_messages = tokio::select! {
            biased;
            _ = send_requests.next() => unreachable!("sends don't complete until responses are received"),
            outgoing = receive_outbound_requests => outgoing
        };

        // Respond to the *second* one promptly.
        let response = ResponseProto {
            id: sent_messages[1].request.as_ref().expect("is request").id,
            status: Some(200),
            message: None,
            headers: vec!["resp-header: value".to_string()],
            body: None,
        };
        inner_responses
            .send(
                Outcome::Continue(MessageEvent::ReceivedMessage(TextOrBinary::Binary(
                    MessageProto::from(ChatMessageProto::Response(response))
                        .encode_to_vec()
                        .into(),
                )))
                .into(),
            )
            .expect("can send response");

        expect_connection_closed(
            fake::POST_REQUEST_TIMEOUT,
            listener_rx,
            (chat_events, inner_responses),
            other_events,
        )
        .await;
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn send_keepalive_on_network_change() {
        let (network_change_event_tx, network_change_event) = tokio::sync::watch::channel(());
        let (listener_tx, _listener_rx) = mpsc::unbounded_channel();
        let (chat, (mut chat_events, _inner_responses)) = fake::new_chat_with_config(
            fake::FakeConfig {
                network_change_event,
                ..Default::default()
            },
            |_| {
                // Behave as if we've switched interfaces immediately after connecting.
                std::future::ready(ip_addr!("192.168.0.1"))
            },
            Box::new(move |evt| {
                let _ = listener_tx.send(evt);
            }),
        );

        assert!(chat.is_connected().await);

        network_change_event_tx.send_replace(());

        let fake::OutgoingMessage(message, _meta) =
            chat_events.recv().await.expect("a request is sent");
        let msg = assert_matches!(message, TextOrBinary::Binary(msg) => msg);
        let decoded = MessageProto::decode(&*msg).expect("valid proto");
        assert_eq!(
            decoded.request.expect("should have request").path(),
            "/v1/keepalive"
        );
    }

    #[test_log::test(tokio::test(start_paused = true))]
    async fn network_change_sender_can_be_dropped() {
        let (network_change_event_tx, network_change_event) = tokio::sync::watch::channel(());
        let (listener_tx, _listener_rx) = mpsc::unbounded_channel();
        let interface_check_count = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&interface_check_count);
        let (chat, (mut chat_events, _inner_responses)) = fake::new_chat_with_config(
            fake::FakeConfig {
                network_change_event,
                ..Default::default()
            },
            move |_| {
                // Behave as if we haven't switched interfaces.
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                tokio::task::yield_now().map(|()| Ipv4Addr::LOCALHOST.into())
            },
            Box::new(move |evt| {
                let _ = listener_tx.send(evt);
            }),
        );

        assert!(chat.is_connected().await);
        tokio::task::yield_now().await;

        // Dropping the sender should prevent any future network events.
        drop(network_change_event_tx);
        tokio::task::yield_now().await;

        let _: tokio::time::error::Elapsed =
            tokio::time::timeout(Duration::from_secs(300), chat_events.recv())
                .await
                .expect_err("should time out");

        assert_eq!(
            interface_check_count.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    #[test_case(futures_util::stream::empty())]
    #[test_case(stream_of_events_other_than_responses())]
    #[test_log::test(tokio::test(start_paused = true, flavor = "current_thread"))]
    async fn do_not_send_keepalive_on_network_change_if_there_is_already_an_outstanding_request(
        other_events: impl Stream<Item = WsEvent>,
    ) {
        let (network_change_event_tx, network_change_event) = tokio::sync::watch::channel(());
        let (listener_tx, listener_rx) = mpsc::unbounded_channel();
        let (chat, (mut chat_events, inner_responses)) = fake::new_chat_with_config(
            fake::FakeConfig {
                network_change_event,
                ..Default::default()
            },
            |_| {
                // Behave as if we've switched interfaces immediately after connecting.
                std::future::ready(ip_addr!("192.168.0.1"))
            },
            Box::new(move |evt| {
                let _ = listener_tx.send(evt);
            }),
        );

        assert!(chat.is_connected().await);

        let request = Request {
            method: Method::GET,
            path: PathAndQuery::from_static("/request"),
            headers: HeaderMap::default(),
            body: None,
        };
        let mut send_request = std::pin::pin!(chat.send(request));

        let receive_outbound_request = async {
            let fake::OutgoingMessage(_message, meta) =
                chat_events.recv().await.expect("not ended");
            let request_id = assert_matches!(&meta, OutgoingMeta::SentRequest(id, _) => *id);
            inner_responses
                .send(Outcome::Continue(MessageEvent::SentMessage(meta)).into())
                .expect("not closed");
            request_id
        };

        // Start polling the client sending future and the server receive end.
        // The client sends won't finish until the response to the request is
        // received, so do't use `join!`. The server receive will complete,
        // though.
        let _sent_request_id = select! {
            biased;
            response = &mut send_request => unreachable!("send finished before responses were sent: {response:?}"),
            req = receive_outbound_request => req,
        };

        // Yield first so the independent client task can record the send,
        // *then* change the network.
        tokio::task::yield_now().await;
        network_change_event_tx.send_replace(());

        expect_connection_closed(
            fake::POST_REQUEST_TIMEOUT,
            listener_rx,
            (chat_events, inner_responses),
            other_events,
        )
        .await;
    }
}
