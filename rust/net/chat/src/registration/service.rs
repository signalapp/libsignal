//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;
use std::fmt::Debug;
use std::future::Future;
use std::panic::UnwindSafe;

use either::Either;
use futures_util::future::BoxFuture;
use futures_util::{FutureExt as _, Stream, StreamExt as _};
use libsignal_net::chat::{
    ChatConnection, ConnectError as ChatConnectError, SendError as ChatSendError,
};
use libsignal_net::infra::errors::{LogSafeDisplay, RetryLater};
use libsignal_net::infra::route::UnsuccessfulOutcome;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Duration, Instant};
use tokio_stream::wrappers::ReceiverStream;

use crate::api::{Registration, Unauth};
use crate::registration::{ChatRequest, ChatResponse, RequestError};
use crate::ws::registration::SendError;

/// Internal connection implementation for the registration client.
///
/// A lazy connection to the Chat service used for making registration requests.
/// When a request is initiated, the existing connection is used or a new one is
/// established. The actual logic runs in a [tokio] task that is communicated
/// with via a channel.
#[derive(derive_more::Debug)]
pub(super) struct RegistrationConnection<'c> {
    #[debug("_")]
    connect_chat: Box<dyn ConnectUnauthChat + Send + Sync + UnwindSafe + 'c>,
    sender: std::sync::Mutex<tokio::sync::mpsc::Sender<IncomingRequest>>,
}

#[derive(Debug)]
pub(super) enum ErrorResponse {
    Connect(FatalConnectError),
    Unexpected { log_safe: String },
    Timeout,
}

impl crate::ws::registration::WsClient for &RegistrationConnection<'_> {
    type SendError = ErrorResponse;

    fn send(
        &self,
        log_tag: &'static str,
        log_safe_path: &str,
        request: ChatRequest,
    ) -> impl Future<Output = Result<ChatResponse, Self::SendError>> {
        self.submit_chat_request(log_tag, log_safe_path, request)
    }
}

/// Describes how to make an unauthenticated [`ChatConnection`].
///
/// This trait is a workaround for lack of AsyncFnMut. Once our MSRV >= 1.85 we
/// can replace this with an `AsyncFnMut` bound.
pub trait ConnectUnauthChat: Send {
    /// Starts an attempt to connect to the Chat server.
    ///
    /// The provided [`oneshot::Sender`] should be dropped if the connection can't
    /// be established or when the connection is lost.
    fn connect_chat(
        &self,
        on_disconnect: oneshot::Sender<Infallible>,
    ) -> BoxFuture<'_, Result<Unauth<ChatConnection>, ChatConnectError>>;
}

impl<'c> RegistrationConnection<'c> {
    /// Attempts to connect to the chat service and send a request.
    ///
    /// This method will retry internally if transient errors are encountered.
    pub(super) async fn connect<E>(
        connect_chat: Box<dyn ConnectUnauthChat + Send + Sync + UnwindSafe + 'c>,
    ) -> Result<Self, RequestError<E>> {
        let (sender, _join_handle) = spawn_connected_chat(&*connect_chat).await?;

        Ok(Self {
            connect_chat,
            sender: sender.into(),
        })
    }

    /// Sends a request on an established connection.
    ///
    /// This method will retry internally if transient errors are encountered.
    async fn submit_chat_request(
        &self,
        _log_tag: &'static str,
        _log_safe_path: &str,
        request: ChatRequest,
    ) -> Result<ChatResponse, ErrorResponse> {
        let Self {
            sender,
            connect_chat,
        } = self;

        let sender = sender.lock().expect("not poisoned").clone();

        let (response, request_sender) =
            send_request(request, &**connect_chat, Some(&sender)).await?;
        *self.sender.lock().expect("not poisoned") = request_sender;

        Ok(response)
    }
}

/// Sends a request to the chat service.
///
/// Uses the provided sender if there is one, otherwise establishes a new
/// connection to the service. Non-fatal connect errors are retried.
async fn send_request(
    request: ChatRequest,
    connect_chat: &(dyn ConnectUnauthChat + Sync),
    mut sender: Option<&mpsc::Sender<IncomingRequest>>,
) -> Result<(ChatResponse, mpsc::Sender<IncomingRequest>), ErrorResponse> {
    loop {
        let sender = match sender.take() {
            Some(sender) => sender.clone(),
            None => {
                let (sender, _join_handle) = spawn_connected_chat(connect_chat)
                    .await
                    .map_err(ErrorResponse::Connect)?;
                sender
            }
        };
        let result = match send_request_to_connected_chat(request.clone(), &sender).await {
            Ok(response) => Ok((response, sender)),
            Err(SendRequestError::ConnectionLost) => {
                log::info!("the connection to the chat server was lost, will retry");
                continue;
            }
            Err(SendRequestError::RequestTimedOut) => Err(ErrorResponse::Timeout),
            Err(SendRequestError::Unknown { log_safe }) => {
                Err(ErrorResponse::Unexpected { log_safe })
            }
        };
        return result;
    }
}

#[derive(Debug, displaydoc::Display)]
pub(super) enum FatalConnectError {
    /// invalid chat client configuration
    InvalidConfiguration,
    /// {0}
    RetryLater(RetryLater),
    /// unexpected error: {0}
    Unexpected(&'static str),
}
impl LogSafeDisplay for FatalConnectError {}

impl<E, D> From<FatalConnectError> for crate::api::RequestError<E, D> {
    fn from(value: FatalConnectError) -> Self {
        match value {
            FatalConnectError::RetryLater(retry_later) => Self::from(retry_later),
            FatalConnectError::InvalidConfiguration | FatalConnectError::Unexpected(_) => {
                Self::Unexpected {
                    log_safe: (&value as &dyn LogSafeDisplay).to_string(),
                }
            }
        }
    }
}
impl SendError for ErrorResponse {
    type DisconnectError = Infallible;
    fn into_request_error<E>(self) -> RequestError<E> {
        match self {
            ErrorResponse::Connect(fatal_connect_error) => fatal_connect_error.into(),
            ErrorResponse::Unexpected { log_safe } => RequestError::Unexpected { log_safe },
            ErrorResponse::Timeout => RequestError::Timeout,
        }
    }
}

const CHAT_CONNECT_DELAY_PARAMS: libsignal_net::infra::route::ConnectionOutcomeParams =
    libsignal_net::infra::route::ConnectionOutcomeParams {
        short_term_age_cutoff: Duration::from_secs(60),
        long_term_age_cutoff: Duration::from_secs(60),
        cooldown_growth_factor: 1.5,
        count_growth_factor: 10.0,
        max_count: 5,
        max_delay: Duration::from_secs(30),
    };

/// Connects to the chat service and spawns a task to manage it.
///
/// Returns a channel for sending requests to it.
async fn spawn_connected_chat(
    connect_chat: &(impl ConnectUnauthChat + ?Sized),
) -> Result<(mpsc::Sender<IncomingRequest>, tokio::task::JoinHandle<()>), FatalConnectError> {
    let mut failure_count = 0;
    let mut last_failure_at = None;

    let (chat, on_disconnect_rx) = loop {
        let (on_disconnect_tx, on_disconnect_rx) = oneshot::channel();

        let chat = match connect_chat.connect_chat(on_disconnect_tx).await {
            Ok(Unauth(chat)) => Registration(chat),
            Err(err) => {
                log::warn!(
                    "registration chat connect failed: {}",
                    (&err as &dyn LogSafeDisplay)
                );
                match err {
                    ChatConnectError::InvalidConnectionConfiguration => {
                        return Err(FatalConnectError::InvalidConfiguration);
                    }
                    ChatConnectError::RetryLater(retry_later) => {
                        return Err(FatalConnectError::RetryLater(retry_later));
                    }
                    err @ (ChatConnectError::Timeout
                    | ChatConnectError::AllAttemptsFailed
                    | ChatConnectError::WebSocket(_)) => {
                        log::warn!("retryable error: {}", (&err as &dyn LogSafeDisplay));
                        let now = Instant::now();
                        let since_last_failure = last_failure_at
                            .replace(now)
                            .map_or(Duration::MAX, |previous_failure| now - previous_failure);
                        let delay = CHAT_CONNECT_DELAY_PARAMS.compute_delay(
                            UnsuccessfulOutcome::ShortTerm,
                            since_last_failure,
                            failure_count,
                        );
                        tokio::time::sleep(delay).await;
                        failure_count += 1;
                        continue;
                    }
                    ChatConnectError::AppExpired => {
                        return Err(FatalConnectError::Unexpected(
                            "unauthenticated socket signaled app expired",
                        ));
                    }
                    ChatConnectError::DeviceDeregistered => {
                        return Err(FatalConnectError::Unexpected(
                            "unauthenticated socket signaled deregistration",
                        ));
                    }
                }
            }
        };

        break (chat, on_disconnect_rx);
    };
    let (sender, receiver) = mpsc::channel(MAX_PENDING_REQUESTS);
    let on_disconnect = on_disconnect_rx.map(|r| match r {
        Err(_recv_error) => (),
    });
    log::info!("successfully connecting chat for registration");
    let handle = tokio::spawn(spawned_task_body(
        chat,
        ReceiverStream::new(receiver),
        on_disconnect,
    ));
    Ok((sender, handle))
}

#[derive(Debug, derive_more::From)]
enum SendRequestError {
    ConnectionLost,
    Unknown { log_safe: String },
    RequestTimedOut,
}

/// Sends the provided request to the Chat server and waits for a response.
///
/// Returns an error if the response is not `Ok` or if the connection to the
/// server fails.
async fn send_request_to_connected_chat(
    request: ChatRequest,
    sender: &mpsc::Sender<IncomingRequest>,
) -> Result<ChatResponse, SendRequestError> {
    let (responder, receiver) = oneshot::channel();
    match sender.send((request.clone(), responder)).await {
        Ok(()) => (),
        Err(_channel_closed) => {
            return Err(SendRequestError::ConnectionLost);
        }
    };

    let result = receiver
        .await
        .map_err(|_: oneshot::error::RecvError| SendRequestError::ConnectionLost)?;

    let response = result.map_err(|err| {
        log::warn!(
            "registration chat request failed: {}",
            (&err as &dyn LogSafeDisplay)
        );
        match err {
            ChatSendError::RequestTimedOut => SendRequestError::RequestTimedOut,
            ChatSendError::Disconnected => SendRequestError::ConnectionLost,
            ChatSendError::ConnectionInvalidated | ChatSendError::ConnectedElsewhere => {
                SendRequestError::Unknown {
                    log_safe: "registration connection unexpectedly closed by server".into(),
                }
            }
            ChatSendError::WebSocket(error) => SendRequestError::Unknown {
                log_safe: format!(
                    "websocket error: {}",
                    <dyn LogSafeDisplay>::to_string(&error)
                ),
            },
            ChatSendError::IncomingDataInvalid => SendRequestError::Unknown {
                log_safe: "received invalid response".into(),
            },
            ChatSendError::RequestHasInvalidHeader => SendRequestError::Unknown {
                log_safe: "request had invalid header".into(),
            },
        }
    })?;

    log::debug!("registration chat request succeeded");
    Ok(response)
}

/// The body of a spawned [`tokio::task`] that handles the given
/// [`ChatConnection`].
///
/// Sends received incoming requests to the provided `ChatConnection` as long as
/// it remains connected. The task handles a single request at a time in the
/// order that they are received. If the `ChatConnection` stops working, or if
/// the `on_disconnect` future resolves, the stream of incoming requests will be
/// dropped. Callers can use that to determine whether the task is still active.
async fn spawned_task_body(
    chat: Registration<ChatConnection>,
    incoming_requests: impl Stream<Item = IncomingRequest> + Send,
    on_disconnect: impl Future<Output = ()>,
) {
    let mut on_disconnect = std::pin::pin!(on_disconnect);

    let incoming_requests = Some(incoming_requests);
    let request_in_progress = None;
    let mut request_in_progress = std::pin::pin!(request_in_progress);
    let mut incoming_requests = std::pin::pin!(incoming_requests);

    loop {
        enum Event {
            RequestFinished,
            Incoming(Result<Option<IncomingRequest>, tokio::time::error::Elapsed>),
            Disconnected,
        }

        let wait_for_event = match request_in_progress.as_mut().as_pin_mut() {
            Some(in_progress) => {
                // Don't poll for more incoming requests when there's one in progress.
                Either::Left(async {
                    in_progress.await;
                    Event::RequestFinished
                })
            }
            None => match incoming_requests.as_mut().as_pin_mut() {
                None => {
                    // There's no request in progress and none are coming in.
                    break;
                }
                Some(mut incoming_requests) => Either::Right(
                    tokio::time::timeout(INACTIVITY_TIMEOUT, async move {
                        incoming_requests.next().await
                    })
                    .map(Event::Incoming),
                ),
            },
        };

        let event = tokio::select! {
            incoming = wait_for_event => incoming,
            () = on_disconnect.as_mut() => Event::Disconnected,
        };

        match event {
            Event::RequestFinished => {
                request_in_progress.set(None);
                // If that was the last request we'll discover that at the top of the loop.
                continue;
            }
            Event::Incoming(Err(_)) => {
                // This only happens when there are no requests in flight.
                log::warn!("registration chat inactivity timeout was reached; disconnecting");
                break;
            }
            Event::Disconnected => {
                // Nothing to do.
                return;
            }
            Event::Incoming(Ok(Some(request))) => {
                let request_fut = start_request(&chat, request);
                request_in_progress.set(Some(request_fut));
            }
            Event::Incoming(Ok(None)) => {
                // Indicate that we won't be getting any more requests.
                incoming_requests.set(None);
            }
        }
    }
    // Drop the incoming requests stream if it's still present so the sender end
    // gets feedback sooner.
    incoming_requests.set(None);

    chat.disconnect().await;
}

/// How long to wait after the last request before disconnecting from Chat.
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(90);

/// How long each request to the Chat server should be allowed to take.
///
/// This doesn't include the amount of time spent connecting to the service in
/// the first place.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The maximum number of requests that can be pending but not sent off yet.
///
/// This can be extremely small since the registration process is serialized;
/// there is no need to have multiple requests in flight at a time.
const MAX_PENDING_REQUESTS: usize = 1;

type IncomingRequest = (
    ChatRequest,
    oneshot::Sender<Result<ChatResponse, ChatSendError>>,
);

async fn start_request(chat: &ChatConnection, (request, mut responder): IncomingRequest) {
    if responder.is_closed() {
        return;
    }
    let result = tokio::select! {
        result = chat.send(request, REQUEST_TIMEOUT) => result,
        () = responder.closed() => return,
    };

    match responder.send(result) {
        Ok(()) => (),
        Err(_failed_to_send) => (),
    }
}

#[cfg(test)]
mod test {
    use std::sync::LazyLock;
    use std::sync::atomic::AtomicUsize;

    use assert_matches::assert_matches;
    use http::HeaderMap;
    use http::uri::PathAndQuery;
    use test_case::test_case;
    use tokio::sync::oneshot;
    use tokio::time::Instant;

    use super::*;
    use crate::registration::testutil::{ConnectChatFn, DropOnDisconnect, FakeChatConnect};

    /// A value to use when we don't care about the contents of the request.
    static SOME_REQUEST: LazyLock<ChatRequest> = LazyLock::new(|| ChatRequest {
        method: http::Method::GET,
        body: None,
        headers: HeaderMap::new(),
        path: PathAndQuery::from_static("/"),
    });

    #[tokio::test(start_paused = true)]
    async fn spawned_task_exits_after_inactivity() {
        let (fake_chat_remote_tx, _fake_chat_remote_rx) = mpsc::unbounded_channel();
        let fake_connect = FakeChatConnect {
            remote: fake_chat_remote_tx,
        };

        let (sender, join_handle) = spawn_connected_chat(&fake_connect)
            .await
            .expect("can connect");

        // With no requests sent to it, the task will hang up after the allowed inactivity period.
        let start = Instant::now();
        let () = join_handle.await.expect("finished gracefully");
        assert_eq!(start.elapsed(), INACTIVITY_TIMEOUT);

        // Trying to send to it now is futile!
        let (tx, _rx) = oneshot::channel();
        sender
            .send((SOME_REQUEST.clone(), tx))
            .await
            .expect_err("remote should have hung up");
    }

    enum DisconnectTime {
        AfterConnectionSpawned,
        AfterRequestSent,
    }
    use DisconnectTime::*;

    #[test_case(AfterConnectionSpawned)]
    #[test_case(AfterRequestSent)]
    #[tokio::test(start_paused = true)]
    async fn spawned_chat_disconnect_results_in_failed_request(when: DisconnectTime) {
        // Make sure that whether the ChatConnection is disconnected before or
        // after the request is sent to the handling task, the client still
        // learns that the request didn't succeed.
        let (fake_chat_remote_tx, mut fake_chat_remote_rx) = mpsc::unbounded_channel();
        let fake_connect = FakeChatConnect {
            remote: fake_chat_remote_tx,
        };

        let (to_send, receive_response) = {
            let (tx, rx) = oneshot::channel();
            let request = ChatRequest {
                method: http::Method::GET,
                body: None,
                headers: HeaderMap::new(),
                path: PathAndQuery::from_static("/"),
            };
            ((request, tx), rx)
        };

        let (sender, _join_handle) = spawn_connected_chat(&fake_connect)
            .await
            .expect("can connect");
        let fake_remote = fake_chat_remote_rx
            .recv()
            .await
            .expect("connection started");

        match when {
            DisconnectTime::AfterConnectionSpawned => {
                fake_remote.send_close(None).expect("client is connected");
                sender.send(to_send).await.expect("task is running");
            }
            DisconnectTime::AfterRequestSent => {
                sender.send(to_send).await.expect("task is running");
                fake_remote.send_close(None).expect("client is connected");
            }
        }
        let response = receive_response.await;

        assert_matches!(response, Err(_) | Ok(Err(_)));
    }

    #[tokio::test(start_paused = true)]
    async fn send_request_retries_connect_on_transient_failure() {
        let (fake_chat_tx, mut fake_chat_rx) = mpsc::unbounded_channel();

        const TRANSIENT_FAILURE: ChatConnectError = ChatConnectError::Timeout;
        const RETRY_COUNT: usize = 3;
        let connect_count = AtomicUsize::new(0);
        let connect_chat = ConnectChatFn::new(|on_disconnect| {
            let count = connect_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::future::ready(if count == RETRY_COUNT - 1 {
                let (fake_chat, fake_remote) = ChatConnection::new_fake(
                    tokio::runtime::Handle::current(),
                    DropOnDisconnect::new(on_disconnect).into_listener(),
                    [],
                );
                fake_chat_tx.send(fake_remote).unwrap();
                Ok(Unauth(fake_chat))
            } else {
                Err(TRANSIENT_FAILURE)
            })
        });

        let send_request = send_request(SOME_REQUEST.clone(), &connect_chat, None);
        let mut send_request = std::pin::pin!(send_request);

        // Get the remote end for the connected fake chat. We need to poll both
        // futures so that the connect attempts get made.
        let fake_remote = tokio::select! {
            _ = send_request.as_mut() => unreachable!("can't finish until remote responds"),
            remote = fake_chat_rx.recv() => remote
        }
        .expect("chat connected");

        let request = fake_remote
            .receive_request()
            .await
            .expect("still connected")
            .expect("request received");

        let response = libsignal_net::chat::ResponseProto {
            id: request.id,
            status: Some(200),
            ..Default::default()
        };
        fake_remote
            .send_response(response)
            .expect("still connected");

        let (_response, connected_sender) = send_request.await.expect("connects after retry");

        assert!(!connected_sender.is_closed());
        assert_eq!(
            connect_count.load(std::sync::atomic::Ordering::SeqCst),
            RETRY_COUNT
        );
    }

    #[tokio::test(start_paused = true)]
    async fn send_request_fails_on_timeout() {
        let (fake_chat_remote_tx, mut fake_chat_remote_rx) = mpsc::unbounded_channel();
        let fake_connect = FakeChatConnect {
            remote: fake_chat_remote_tx,
        };

        let send_request = send_request(SOME_REQUEST.clone(), &fake_connect, None);
        let mut send_request = std::pin::pin!(send_request);

        // Get the remote end for the connected fake chat. We need to poll both
        // futures so that the connect attempts get made.
        let fake_remote = tokio::select! {
            _ = send_request.as_mut() => unreachable!("can't finish until remote responds"),
            remote = fake_chat_remote_rx.recv() => remote
        }
        .expect("chat connected");

        let _request = fake_remote
            .receive_request()
            .await
            .expect("still connected")
            .expect("request received");

        // If we wait long enough the request will time out.
        let result = send_request.await;

        assert_matches!(result, Err(ErrorResponse::Timeout));
    }

    #[tokio::test(start_paused = true)]
    async fn request_sent_to_task_cancelled_before_send() {
        let (fake_chat_remote_tx, mut fake_chat_remote_rx) = mpsc::unbounded_channel();
        let fake_connect = FakeChatConnect {
            remote: fake_chat_remote_tx,
        };

        let (request_sender, _join_handle) = spawn_connected_chat(&fake_connect)
            .await
            .expect("can connect");
        let fake_chat_remote = fake_chat_remote_rx.recv().await.unwrap();

        let mut first_send_fut = std::pin::pin!(send_request_to_connected_chat(
            ChatRequest {
                path: PathAndQuery::from_static("/1"),
                ..SOME_REQUEST.clone()
            },
            &request_sender,
        ));

        // Receive the request but don't respond to it until the second request
        // has been put in the stream for the task. We need to poll both tasks
        // so the send makes progress.
        let request = tokio::select! {
            request = fake_chat_remote.receive_request() => request,
            _ = first_send_fut.as_mut() => unreachable!("can't finish without response")
        }
        .expect("still connected")
        .expect("request received");
        assert_eq!(request.path.as_deref(), Some("/1"));

        {
            // Scope to limit the lifetime of the second send future
            let mut second_send_fut = std::pin::pin!(send_request_to_connected_chat(
                ChatRequest {
                    path: PathAndQuery::from_static("/2"),
                    ..SOME_REQUEST.clone()
                },
                &request_sender,
            ));
            let _ = futures_util::poll!(&mut second_send_fut);
            assert_matches!(fake_chat_remote.receive_request().now_or_never(), None);

            // Cancelling the second request now by ending its scope, before the
            // actual bytes are put "on the wire", should result in it never being
            // sent.
        }

        // Send some response to the first request.
        fake_chat_remote
            .send_response(libsignal_net::chat::ResponseProto {
                id: request.id,
                status: Some(200),
                ..Default::default()
            })
            .expect("still connected");
        let _response = first_send_fut.await;

        // The task should reach its inactivity timeout and disconnect.
        assert_matches!(fake_chat_remote.receive_request().await, Ok(None));
    }
}
