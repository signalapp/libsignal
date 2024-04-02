//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto as _;
use std::future::Future;
use std::num::{NonZeroU16, NonZeroU32};
use std::panic::RefUnwindSafe;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use base64::prelude::{Engine, BASE64_STANDARD};
use futures_util::future::TryFutureExt as _;
use http::uri::{InvalidUri, PathAndQuery};
use http::{HeaderMap, HeaderName, HeaderValue};
use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_net::auth::Auth;
use libsignal_net::chat::{
    chat_service, ChatServiceError, ChatServiceWithDebugInfo, DebugInfo as ChatServiceDebugInfo,
    Request, Response as ChatResponse,
};
use libsignal_net::enclave::{
    Cdsi, EnclaveEndpoint, EnclaveEndpointConnection, EnclaveKind, Nitro, PpssSetup, Sgx, Tpm2Snp,
};
use libsignal_net::env::{Env, Svr3Env};
use libsignal_net::infra::connection_manager::MultiRouteConnectionManager;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::tcp_ssl::{
    DirectConnector as TcpSslDirectConnector, TcpSslConnector, TcpSslConnectorStream,
};
use libsignal_net::infra::{make_ws_config, EndpointConnection};
use libsignal_net::svr::{self, SvrConnection};
use libsignal_net::svr3::{self, OpaqueMaskedShareSet, PpssOps as _};
use libsignal_net::{chat, env};
use rand::rngs::OsRng;
use tokio::sync::mpsc;

use crate::support::*;
use crate::*;

pub(crate) mod cdsi;

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
    chat: EndpointConnection<MultiRouteConnectionManager>,
    cdsi: EnclaveEndpointConnection<Cdsi, MultiRouteConnectionManager>,
    svr3: (
        EnclaveEndpointConnection<Sgx, MultiRouteConnectionManager>,
        EnclaveEndpointConnection<Nitro, MultiRouteConnectionManager>,
        EnclaveEndpointConnection<Tpm2Snp, MultiRouteConnectionManager>,
    ),
    transport_connector: std::sync::Mutex<TcpSslConnector>,
}

impl RefUnwindSafe for ConnectionManager {}

impl ConnectionManager {
    const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    fn new(environment: Environment) -> Self {
        let dns_resolver =
            DnsResolver::new_with_static_fallback(environment.env().static_fallback());
        let transport_connector =
            std::sync::Mutex::new(TcpSslDirectConnector::new(dns_resolver).into());
        let chat_endpoint = PathAndQuery::from_static(env::constants::WEB_SOCKET_PATH);
        let chat_connection_params = environment
            .env()
            .chat_domain_config
            .connection_params_with_fallback();
        let chat_ws_config = make_ws_config(chat_endpoint, Self::DEFAULT_CONNECT_TIMEOUT);
        Self {
            chat: EndpointConnection::new_multi(
                chat_connection_params,
                Self::DEFAULT_CONNECT_TIMEOUT,
                chat_ws_config,
            ),
            cdsi: Self::endpoint_connection(environment.env().cdsi),
            svr3: (
                Self::endpoint_connection(environment.env().svr3.sgx()),
                Self::endpoint_connection(environment.env().svr3.nitro()),
                Self::endpoint_connection(environment.env().svr3.tpm2snp()),
            ),
            transport_connector,
        }
    }

    fn endpoint_connection<E: EnclaveKind>(
        endpoint: EnclaveEndpoint<'static, E>,
    ) -> EnclaveEndpointConnection<E, MultiRouteConnectionManager> {
        let params = endpoint.domain_config.connection_params_with_fallback();
        EnclaveEndpointConnection::new_multi(
            endpoint.mr_enclave,
            params,
            Self::DEFAULT_CONNECT_TIMEOUT,
        )
    }
}

#[bridge_fn]
fn ConnectionManager_new(environment: AsType<Environment, u8>) -> ConnectionManager {
    ConnectionManager::new(environment.into_inner())
}

#[bridge_fn]
fn ConnectionManager_set_proxy(
    connection_manager: &ConnectionManager,
    host: String,
    port: AsType<NonZeroU16, u16>,
) {
    let port = port.into_inner();
    let proxy_addr = (host.as_str(), port);
    let mut guard = connection_manager
        .transport_connector
        .lock()
        .expect("not poisoned");
    match &mut *guard {
        TcpSslConnector::Direct(direct) => *guard = direct.with_proxy(proxy_addr).into(),
        TcpSslConnector::Proxied(proxied) => proxied.set_proxy(proxy_addr),
    };
}

#[bridge_fn]
fn ConnectionManager_clear_proxy(connection_manager: &ConnectionManager) {
    let mut guard = connection_manager
        .transport_connector
        .lock()
        .expect("not poisoned");
    match &*guard {
        TcpSslConnector::Direct(_direct) => (),
        TcpSslConnector::Proxied(proxied) => {
            *guard = TcpSslDirectConnector::new(proxied.dns_resolver.clone()).into()
        }
    };
}

bridge_handle!(ConnectionManager, clone = false);

#[bridge_fn]
fn CreateOTP(username: String, secret: &[u8]) -> String {
    Auth::otp(&username, secret, std::time::SystemTime::now())
}

#[bridge_fn]
fn CreateOTPFromBase64(username: String, secret: String) -> String {
    let secret = BASE64_STANDARD.decode(secret).expect("valid base64");
    Auth::otp(&username, &secret, std::time::SystemTime::now())
}

#[bridge_io(TokioAsyncContext)]
async fn Svr3Backup(
    connection_manager: &ConnectionManager,
    secret: Box<[u8]>,
    password: String,
    max_tries: AsType<NonZeroU32, u32>,
    username: String,         // hex-encoded uid
    enclave_password: String, // timestamp:otp(...)
) -> Result<Vec<u8>, svr3::Error> {
    let secret = secret
        .as_ref()
        .try_into()
        .expect("can only backup 32 bytes");
    let mut rng = OsRng;
    let share_set = svr3_connect(connection_manager, username, enclave_password)
        .map_err(|err| err.into())
        .and_then(|connections| {
            Svr3Env::backup(
                connections,
                &password,
                secret,
                max_tries.into_inner(),
                &mut rng,
            )
        })
        .await?;
    Ok(share_set.serialize().expect("can serialize the share set"))
}

#[bridge_io(TokioAsyncContext)]
async fn Svr3Restore(
    connection_manager: &ConnectionManager,
    password: String,
    share_set: Box<[u8]>,
    username: String,         // hex-encoded uid
    enclave_password: String, // timestamp:otp(...)
) -> Result<Vec<u8>, svr3::Error> {
    let mut rng = OsRng;
    let share_set = OpaqueMaskedShareSet::deserialize(&share_set)?;
    let restored_secret = svr3_connect(connection_manager, username, enclave_password)
        .map_err(|err| err.into())
        .and_then(|connections| Svr3Env::restore(connections, &password, share_set, &mut rng))
        .await?;
    Ok(restored_secret.to_vec())
}

async fn svr3_connect<'a>(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
) -> Result<<Svr3Env<'a> as PpssSetup<TcpSslConnectorStream>>::Connections, svr::Error> {
    let auth = Auth { username, password };
    let ConnectionManager {
        chat: _chat,
        cdsi: _cdsi,
        svr3: (sgx, nitro, tpm2snp),
        transport_connector,
    } = connection_manager;
    let transport_connector = transport_connector.lock().expect("not poisoned").clone();
    let sgx = SvrConnection::connect(auth.clone(), sgx, transport_connector.clone()).await?;
    let nitro = SvrConnection::connect(auth.clone(), nitro, transport_connector.clone()).await?;
    let tpm2snp = SvrConnection::connect(auth, tpm2snp, transport_connector).await?;
    Ok((sgx, nitro, tpm2snp))
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
    let (incoming_tx, _incoming_rx) = mpsc::channel(1);
    Chat {
        service: chat_service(
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

#[bridge_io(TokioAsyncContext)]
async fn ChatService_unauth_send_and_debug(
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

    use test_case::test_case;

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

    #[test_case(Environment::Staging; "staging")]
    #[test_case(Environment::Prod; "prod")]
    fn can_create_connection_manager(env: Environment) {
        let _ = ConnectionManager::new(env);
    }
}
