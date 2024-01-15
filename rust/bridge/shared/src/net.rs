//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::TryInto as _;
use std::future::Future;
use std::time::Duration;

use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_net::cdsi::{
    self, AciAndAccessKey, Auth, CdsiConnection, ClientResponseCollector, LookupResponse, Token,
    E164,
};
use libsignal_net::enclave::{Cdsi, EndpointConnection};
use libsignal_net::env::{Env, Svr3Env};
use libsignal_net::infra::certs::RootCertificates;
use libsignal_net::infra::connection_manager::MultiRouteConnectionManager;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::errors::NetError;
use libsignal_net::infra::{
    ConnectionParams, HttpRequestDecorator, HttpRequestDecoratorSeq, TcpSslTransportConnector,
};
use libsignal_net::utils::timeout;
use libsignal_protocol::{Aci, SignalProtocolError};

use crate::support::*;
use crate::*;

pub struct TokioAsyncContext(tokio::runtime::Runtime);

#[bridge_fn(ffi = false)]
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
pub enum Environment {
    Staging = 0,
    Prod = 1,
}

impl Environment {
    fn env(&self) -> Env<'static, Svr3Env> {
        match self {
            Self::Staging => libsignal_net::env::STAGING,
            Self::Prod => libsignal_net::env::PROD,
        }
    }

    fn cdsi_fallback_connection_params(self) -> Vec<ConnectionParams> {
        match self {
            Environment::Prod => vec![
                ConnectionParams {
                    sni: "inbox.google.com".into(),
                    host: "reflector-nrgwuv7kwq-uc.a.run.app".into(),
                    port: 443,
                    http_request_decorator: HttpRequestDecorator::PathPrefix("/service").into(),
                    certs: RootCertificates::Native,
                    dns_resolver: DnsResolver::System,
                },
                ConnectionParams {
                    sni: "pintrest.com".into(),
                    host: "chat-signal.global.ssl.fastly.net".into(),
                    port: 443,
                    http_request_decorator: HttpRequestDecoratorSeq::default(),
                    certs: RootCertificates::Native,
                    dns_resolver: DnsResolver::System,
                },
            ],
            Environment::Staging => vec![ConnectionParams {
                sni: "inbox.google.com".into(),
                host: "reflector-nrgwuv7kwq-uc.a.run.app".into(),
                port: 443,
                http_request_decorator: HttpRequestDecorator::PathPrefix("/service-staging").into(),
                certs: RootCertificates::Native,
                dns_resolver: DnsResolver::System,
            }],
        }
    }
}

pub struct ConnectionManager {
    cdsi: EndpointConnection<Cdsi, MultiRouteConnectionManager, TcpSslTransportConnector>,
}

impl ConnectionManager {
    const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    fn new(environment: Environment) -> Self {
        let cdsi_endpoint = environment.env().cdsi;
        let direct_connection = cdsi_endpoint.direct_connection();
        let connection_params: Vec<_> = [direct_connection]
            .into_iter()
            .chain(environment.cdsi_fallback_connection_params())
            .collect();

        Self {
            cdsi: EndpointConnection::new_multi(
                cdsi_endpoint.mr_enclave,
                connection_params,
                Self::DEFAULT_CONNECT_TIMEOUT,
                TcpSslTransportConnector,
            ),
        }
    }
}

#[bridge_fn]
pub fn ConnectionManager_new(environment: u8) -> ConnectionManager {
    ConnectionManager::new(environment.try_into().expect("is valid environment value"))
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
fn LookupRequest_setToken(
    request: &LookupRequest,
    token: &[u8],
) -> Result<(), SignalProtocolError> {
    request.0.lock().expect("not poisoned").token = token.into();
    Ok(())
}

#[bridge_fn]
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
fn LookupRequest_setReturnAcisWithoutUaks(
    request: &LookupRequest,
    return_acis_without_uaks: bool,
) -> Result<(), SignalProtocolError> {
    request
        .0
        .lock()
        .expect("not poisoned")
        .return_acis_without_uaks = return_acis_without_uaks;
    Ok(())
}

bridge_handle!(LookupRequest, clone = false);

pub struct CdsiLookup {
    token: Token,
    remaining: std::sync::Mutex<Option<ClientResponseCollector>>,
}
bridge_handle!(CdsiLookup, clone = false);

#[bridge_io(TokioAsyncContext, ffi = false)]
async fn CdsiLookup_new(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
    request: &LookupRequest,
    timeout_millis: u32,
) -> Result<CdsiLookup, cdsi::Error> {
    let request = std::mem::take(&mut *request.0.lock().expect("not poisoned"));
    let auth = Auth { username, password };

    let connected = CdsiConnection::connect(&connection_manager.cdsi, auth).await?;
    let (token, remaining_response) = timeout(
        Duration::from_millis(timeout_millis.into()),
        cdsi::Error::Net(NetError::Timeout),
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

#[bridge_io(TokioAsyncContext, ffi = false)]
async fn CdsiLookup_complete(lookup: &CdsiLookup) -> Result<LookupResponse, cdsi::Error> {
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
