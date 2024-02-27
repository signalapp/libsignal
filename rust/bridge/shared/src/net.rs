//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto as _;
use std::future::Future;
use std::panic::RefUnwindSafe;
use std::sync::Arc;
use std::time::Duration;

use http::uri::PathAndQuery;
use http::{HeaderMap, HeaderName, HeaderValue};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use base64::prelude::{Engine, BASE64_STANDARD};
use cfg_if::cfg_if;

use libsignal_bridge_macros::{bridge_fn, bridge_fn_void, bridge_io};
use libsignal_net::auth::Auth;
use libsignal_net::cdsi::{
    self, AciAndAccessKey, CdsiConnection, ClientResponseCollector, LookupResponse, Token, E164,
};
use libsignal_net::chat::ws::{ChatOverWebSocketServiceConnector, ServerRequest};
use libsignal_net::chat::{chat_service, ChatServiceWithDebugInfo, DebugInfo, Request, Response};
use libsignal_net::enclave::{Cdsi, EnclaveEndpoint, EnclaveEndpointConnection, EnclaveKind};
use libsignal_net::env::{Env, Svr3Env};
use libsignal_net::infra::connection_manager::MultiRouteConnectionManager;
use libsignal_net::infra::errors::NetError;
use libsignal_net::infra::ws::WebSocketClientConnector;
use libsignal_net::infra::{make_ws_config, EndpointConnection, TcpSslTransportConnector};
use libsignal_net::utils::timeout;
use libsignal_net::{chat, env};
use libsignal_protocol::{Aci, SignalProtocolError};

use crate::support::*;
use crate::*;

cfg_if! {
    if #[cfg(any(feature = "jni", feature = "node"))] {
        use futures_util::future::TryFutureExt as _;
        use rand::rngs::OsRng;
        use std::num::NonZeroU32;
        use libsignal_net::enclave::{ Nitro, PpssSetup, Sgx, };
        use libsignal_net::svr::{self, SvrConnection};
        use libsignal_net::svr3::{self, OpaqueMaskedShareSet, PpssOps as _};
    }
}

pub struct TokioAsyncContext(tokio::runtime::Runtime);

/// Assert [`TokioAsyncContext`] is unwind-safe.
///
/// [`tokio::runtime::Runtime`] handles panics in spawned tasks internally, and
/// spawning a task on it shouldn't cause logic errors if that panics.
impl std::panic::RefUnwindSafe for TokioAsyncContext {}

#[bridge_fn]
fn TokioAsyncContext_new() -> TokioAsyncContext {
    TokioAsyncContext(tokio::runtime::Runtime::new().expect("failed to create runtime"))
}

impl<F> AsyncRuntime<F> for TokioAsyncContext
where
    F: Future + Send + 'static,
    F::Output: ResultReporter + Send,
    <F::Output as ResultReporter>::Receiver: Send,
{
    fn run_future(&self, future: F, completer: <F::Output as ResultReporter>::Receiver) {
        let handle = self.0.handle().clone();
        #[allow(clippy::let_underscore_future)]
        let _: tokio::task::JoinHandle<()> = self.0.spawn(async move {
            let completed = future.await;
            let _: tokio::task::JoinHandle<()> =
                handle.spawn_blocking(move || completed.report_to(completer));
        });
    }
}

bridge_handle!(TokioAsyncContext, clone = false);

#[derive(num_enum::TryFromPrimitive)]
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum Environment {
    Staging = 0,
    Prod = 1,
}

impl Environment {
    fn env<'a>(self) -> Env<'a, Svr3Env<'a>> {
        match self {
            Self::Staging => libsignal_net::env::STAGING,
            Self::Prod => libsignal_net::env::PROD,
        }
    }
}

pub struct ConnectionManager {
    chat: EndpointConnection<
        MultiRouteConnectionManager,
        ChatOverWebSocketServiceConnector<TcpSslTransportConnector>,
    >,
    cdsi: EnclaveEndpointConnection<Cdsi, MultiRouteConnectionManager, TcpSslTransportConnector>,
    #[cfg(any(feature = "jni", feature = "node"))]
    svr3: (
        EnclaveEndpointConnection<Sgx, MultiRouteConnectionManager, TcpSslTransportConnector>,
        EnclaveEndpointConnection<Nitro, MultiRouteConnectionManager, TcpSslTransportConnector>,
    ),
}

impl RefUnwindSafe for ConnectionManager {}

impl ConnectionManager {
    const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    fn new(environment: Environment) -> Self {
        let chat_endpoint = PathAndQuery::from_static(env::constants::WEB_SOCKET_PATH);
        let chat_connection_params = environment
            .env()
            .chat_domain_config
            .connection_params_with_fallback();
        let (incoming_tx, _incoming_rx) =
            mpsc::channel::<ServerRequest<tokio_boring::SslStream<TcpStream>>>(1);
        let chat_connector = ChatOverWebSocketServiceConnector::new(
            WebSocketClientConnector::new(
                TcpSslTransportConnector,
                make_ws_config(chat_endpoint, Self::DEFAULT_CONNECT_TIMEOUT),
            ),
            incoming_tx,
        );
        Self {
            chat: EndpointConnection::new_multi(
                chat_connection_params,
                Self::DEFAULT_CONNECT_TIMEOUT,
                chat_connector,
            ),
            cdsi: Self::endpoint_connection(environment.env().cdsi),
            #[cfg(any(feature = "jni", feature = "node"))]
            svr3: (
                Self::endpoint_connection(environment.env().svr3.sgx()),
                Self::endpoint_connection(environment.env().svr3.nitro()),
            ),
        }
    }

    fn endpoint_connection<E: EnclaveKind>(
        endpoint: EnclaveEndpoint<'static, E>,
    ) -> EnclaveEndpointConnection<E, MultiRouteConnectionManager, TcpSslTransportConnector> {
        let params = endpoint.domain_config.connection_params_with_fallback();
        EnclaveEndpointConnection::new_multi(
            endpoint.mr_enclave,
            params,
            Self::DEFAULT_CONNECT_TIMEOUT,
            TcpSslTransportConnector,
        )
    }
}

#[bridge_fn]
fn ConnectionManager_new(environment: AsType<Environment, u8>) -> ConnectionManager {
    ConnectionManager::new(environment.into_inner())
}

bridge_handle!(ConnectionManager, clone = false);

#[derive(Default)]
pub struct LookupRequest(std::sync::Mutex<cdsi::LookupRequest>);

#[bridge_fn]
fn LookupRequest_new() -> LookupRequest {
    LookupRequest::default()
}

#[bridge_fn]
fn LookupRequest_addE164(request: &LookupRequest, e164: E164) {
    request.0.lock().expect("not poisoned").new_e164s.push(e164)
}

#[bridge_fn]
fn LookupRequest_addPreviousE164(request: &LookupRequest, e164: E164) {
    request
        .0
        .lock()
        .expect("not poisoned")
        .prev_e164s
        .push(e164)
}

#[bridge_fn]
fn LookupRequest_setToken(request: &LookupRequest, token: &[u8]) {
    request.0.lock().expect("not poisoned").token = token.into();
}

#[bridge_fn_void]
fn LookupRequest_addAciAndAccessKey(
    request: &LookupRequest,
    aci: Aci,
    access_key: &[u8],
) -> Result<(), SignalProtocolError> {
    let access_key = access_key
        .try_into()
        .map_err(|_: std::array::TryFromSliceError| {
            SignalProtocolError::InvalidArgument("access_key has wrong number of bytes".to_string())
        })?;
    request
        .0
        .lock()
        .expect("not poisoned")
        .acis_and_access_keys
        .push(AciAndAccessKey { aci, access_key });
    Ok(())
}

#[bridge_fn]
fn LookupRequest_setReturnAcisWithoutUaks(request: &LookupRequest, return_acis_without_uaks: bool) {
    request
        .0
        .lock()
        .expect("not poisoned")
        .return_acis_without_uaks = return_acis_without_uaks;
}

bridge_handle!(LookupRequest, clone = false);

pub struct CdsiLookup {
    token: Token,
    remaining: std::sync::Mutex<Option<ClientResponseCollector>>,
}
bridge_handle!(CdsiLookup, clone = false);

#[bridge_io(TokioAsyncContext)]
async fn CdsiLookup_new(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
    request: &LookupRequest,
    timeout_millis: u32,
) -> Result<CdsiLookup, cdsi::LookupError> {
    let request = std::mem::take(&mut *request.0.lock().expect("not poisoned"));
    let auth = Auth { username, password };

    let connected = CdsiConnection::connect(&connection_manager.cdsi, auth).await?;
    let (token, remaining_response) = timeout(
        Duration::from_millis(timeout_millis.into()),
        cdsi::LookupError::Net(NetError::Timeout),
        connected.send_request(request),
    )
    .await?;

    Ok(CdsiLookup {
        token,
        remaining: std::sync::Mutex::new(Some(remaining_response)),
    })
}

#[bridge_fn]
fn CdsiLookup_token(lookup: &CdsiLookup) -> &[u8] {
    &lookup.token.0
}

#[bridge_io(TokioAsyncContext)]
async fn CdsiLookup_complete(lookup: &CdsiLookup) -> Result<LookupResponse, cdsi::LookupError> {
    let CdsiLookup {
        token: _,
        remaining,
    } = lookup;

    let remaining = remaining
        .lock()
        .expect("not poisoned")
        .take()
        .expect("not completed yet");

    remaining.collect().await
}

#[bridge_fn]
fn CreateOTP(username: String, secret: &[u8]) -> String {
    Auth::otp(&username, secret, std::time::SystemTime::now())
}

#[bridge_fn]
fn CreateOTPFromBase64(username: String, secret: String) -> String {
    let secret = BASE64_STANDARD.decode(secret).expect("valid base64");
    Auth::otp(&username, &secret, std::time::SystemTime::now())
}

#[bridge_io(TokioAsyncContext, ffi = false)]
async fn Svr3Backup(
    connection_manager: &ConnectionManager,
    secret: Box<[u8]>,
    password: String,
    max_tries: AsType<NonZeroU32, u32>,
    username: String,         // hex-encoded uid
    enclave_password: String, // timestamp:otp(...)
    op_timeout_ms: u32,       // timeout spans both connecting and performing the operation
) -> Result<Vec<u8>, svr3::Error> {
    let secret = secret
        .as_ref()
        .try_into()
        .expect("can only backup 32 bytes");
    let mut rng = OsRng;
    let share_set = timeout(
        Duration::from_millis(op_timeout_ms.into()),
        svr::Error::Net(NetError::Timeout).into(),
        svr3_connect(connection_manager, username, enclave_password)
            .map_err(|err| err.into())
            .and_then(|connections| {
                Svr3Env::backup(
                    connections,
                    &password,
                    secret,
                    max_tries.into_inner(),
                    &mut rng,
                )
            }),
    )
    .await?;
    Ok(share_set.serialize().expect("can serialize the share set"))
}

#[bridge_io(TokioAsyncContext, ffi = false)]
async fn Svr3Restore(
    connection_manager: &ConnectionManager,
    password: String,
    share_set: Box<[u8]>,
    username: String,         // hex-encoded uid
    enclave_password: String, // timestamp:otp(...)
    op_timeout_ms: u32,       // timeout spans both connecting and performing the operation
) -> Result<Vec<u8>, svr3::Error> {
    let mut rng = OsRng;
    let share_set = OpaqueMaskedShareSet::deserialize(&share_set)?;
    let restored_secret = timeout(
        Duration::from_millis(op_timeout_ms.into()),
        svr::Error::Net(NetError::Timeout).into(),
        svr3_connect(connection_manager, username, enclave_password)
            .map_err(|err| err.into())
            .and_then(|connections| Svr3Env::restore(connections, &password, share_set, &mut rng)),
    )
    .await?;
    Ok(restored_secret.to_vec())
}

#[cfg(any(feature = "jni", feature = "node"))]
async fn svr3_connect<'a>(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<<Svr3Env<'a> as PpssSetup>::Connections, svr::Error> {
    let auth = Auth { username, password };
    let ConnectionManager {
        chat: _chat,
        cdsi: _cdsi,
        svr3: (sgx, nitro),
    } = connection_manager;
    let sgx = SvrConnection::connect(auth.clone(), sgx).await?;
    let nitro = SvrConnection::connect(auth, nitro).await?;
    Ok((sgx, nitro))
}

pub struct Chat {
    service: chat::Chat<
        Arc<dyn ChatServiceWithDebugInfo + Send + Sync>,
        Arc<dyn ChatServiceWithDebugInfo + Send + Sync>,
    >,
}

impl RefUnwindSafe for Chat {}

pub struct HttpRequest {
    pub method: http::Method,
    pub path: PathAndQuery,
    pub body: Option<Box<[u8]>>,
    pub headers: std::sync::Mutex<HeaderMap>,
}

pub struct ResponseAndDebugInfo {
    pub response: Response,
    pub debug_info: DebugInfo,
}

bridge_handle!(Chat, clone = false);
bridge_handle!(HttpRequest, clone = false);

#[bridge_fn(ffi = false, jni = false)]
fn HttpRequest_new(
    method: String,
    path: String,
    body_as_slice: Option<&[u8]>,
) -> Result<HttpRequest, NetError> {
    let body = body_as_slice.map(|slice| slice.to_vec().into_boxed_slice());
    let method = http::Method::try_from(method.as_str())
        .map_err(|_| NetError::InvalidHttpRequestComponent)?;
    let path =
        PathAndQuery::try_from(path.as_str()).map_err(|_| NetError::InvalidHttpRequestComponent)?;
    Ok(HttpRequest {
        method,
        path,
        body,
        headers: Default::default(),
    })
}

#[bridge_fn(ffi = false, jni = false)]
fn HttpRequest_add_header(
    request: &HttpRequest,
    name: String,
    value: String,
) -> Result<(), NetError> {
    let mut guard = request.headers.lock().expect("not poisoned");
    let header_key =
        HeaderName::try_from(name).map_err(|_| NetError::InvalidHttpRequestComponent)?;
    let header_value =
        HeaderValue::try_from(value).map_err(|_| NetError::InvalidHttpRequestComponent)?;
    (*guard).append(header_key, header_value);
    Ok(())
}

#[bridge_fn(ffi = false, jni = false)]
fn ChatService_new(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Chat {
    Chat {
        service: chat_service(&connection_manager.chat, username, password).into_dyn(),
    }
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn ChatService_disconnect(chat: &Chat) {
    chat.service.disconnect().await
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn ChatService_unauth_send(
    chat: &Chat,
    http_request: &HttpRequest,
    timeout_millis: u32,
) -> Result<Response, NetError> {
    let headers = http_request.headers.lock().expect("not poisoned").clone();
    let request = Request {
        method: http_request.method.clone(),
        path: http_request.path.clone(),
        headers,
        body: http_request.body.clone(),
    };
    chat.service
        .send_unauthenticated(request, Duration::from_millis(timeout_millis.into()))
        .await
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn ChatService_unauth_send_and_debug(
    chat: &Chat,
    http_request: &HttpRequest,
    timeout_millis: u32,
) -> Result<ResponseAndDebugInfo, NetError> {
    let headers = http_request.headers.lock().expect("not poisoned").clone();
    let request = Request {
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

#[cfg(test)]
mod test {
    use std::future::Future;
    use std::sync::{Arc, Mutex};

    use tokio::sync::{mpsc, oneshot};

    use super::*;

    /// [`ResultReporter`] that notifies when it starts reporting.
    struct NotifyingReporter<R> {
        on_start_reporting: oneshot::Sender<()>,
        reporter: R,
    }

    impl<R: ResultReporter> ResultReporter for NotifyingReporter<R> {
        type Receiver = R::Receiver;
        fn report_to(self, completer: Self::Receiver) {
            self.on_start_reporting
                .send(())
                .expect("listener not dropped");
            self.reporter.report_to(completer)
        }
    }

    impl<T> ResultReporter for (T, Arc<Mutex<Option<T>>>) {
        type Receiver = ();
        fn report_to(self, (): ()) {
            *self.1.lock().expect("not poisoned") = Some(self.0);
        }
    }

    fn sum_task<T: std::ops::Add>() -> (
        mpsc::UnboundedSender<(T, T)>,
        mpsc::UnboundedReceiver<T::Output>,
        impl Future<Output = ()>,
    ) {
        let (input_tx, mut input_rx) = mpsc::unbounded_channel();
        let (output_tx, output_rx) = mpsc::unbounded_channel();
        let future = async move {
            while let Some((a, b)) = input_rx.recv().await {
                output_tx.send(a + b).expect("receiver available");
            }
        };

        (input_tx, output_rx, future)
    }

    #[test]
    fn async_tokio_runtime_reporting_does_not_block() {
        // We want to prove that even if result reporting blocks, other tasks on
        // the same runtime can make progress. We can verify this with a task
        // that will sum anything we send it. We then check that if another task
        // is blocked on reporting its result, the summing task still works.

        // Create a runtime with one worker thread running in the background.
        let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
        runtime_builder.worker_threads(1);
        let runtime = runtime_builder.build().expect("valid runtime");

        // Create a task that will sum anything it is sent.
        let (sum_tx, mut sum_rx, sum_future) = sum_task();
        runtime.spawn(sum_future);

        let async_context = TokioAsyncContext(runtime);

        let (send_to_task, task_output, when_reporting) = {
            let (sender, receiver) = oneshot::channel();
            let (on_start_reporting, when_reporting) = oneshot::channel();
            let output = Arc::new(Mutex::new(None));
            let task_output = output.clone();
            async_context.run_future(
                async move {
                    let result = receiver.await.expect("sender not dropped");

                    NotifyingReporter {
                        on_start_reporting,
                        reporter: (result, task_output.clone()),
                    }
                },
                (),
            );
            (sender, output, when_reporting)
        };

        // Now both futures are running, so we should be able to communicate
        // with the sum task.
        sum_tx.send((100, 10)).expect("receiver running");
        sum_tx.send((80, 90)).expect("receiver running");
        assert_eq!(sum_rx.blocking_recv(), Some(110));
        assert_eq!(sum_rx.blocking_recv(), Some(170));

        const FUTURE_RESULT: &str = "eventual result";

        // Lock the mutex and allow the future to complete and to begin the
        // reporting phase. Reporting will be blocked, but the sum task should
        // still be able to make progress.
        let lock = task_output.lock().expect("not poisoned");
        send_to_task.send(FUTURE_RESULT).expect("task is running");
        assert_eq!(*lock, None);
        when_reporting.blocking_recv().expect("sender exists");

        sum_tx.send((300, 33)).expect("receiver exists");
        assert_eq!(sum_rx.blocking_recv(), Some(333));

        // Unlock the mutex. This will allow the result to be reported.
        drop(lock);
        // Dropping the runtime will block waiting for all blocking tasks to
        // finish.
        drop(async_context);
        let result = Arc::into_inner(task_output)
            .expect("no other references")
            .into_inner()
            .expect("not poisoned");
        assert_eq!(result, Some(FUTURE_RESULT));
    }
}
