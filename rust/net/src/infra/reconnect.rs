//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use derive_where::derive_where;
use tokio::sync::Mutex;
use tokio::time::{timeout_at, Instant};
use tokio_util::sync::CancellationToken;

use crate::infra::connection_manager::{ConnectionAttemptOutcome, ConnectionManager};
use crate::infra::errors::LogSafeDisplay;
use crate::infra::{ConnectionParams, HttpRequestDecorator};

/// For a service that needs to go through some initialization procedure
/// before it's ready for use, this enum describes its possible states.
#[derive(Clone, Debug)]
pub enum ServiceState<T, E> {
    /// Contains an instance of the service which is initialized and ready to use.
    /// Also, since we're not actively listening for the event of service going inactive,
    /// the `ServiceStatus` could be used to see if the service is actually running.
    Active(T, ServiceStatus<E>),
    /// The service is inactive and no initialization attempts are to be made
    /// until the `Instant` held by this object.
    Cooldown(Instant),
    /// Last connection attempt resulted in an error.
    Error(E),
    /// Last connection attempt timed out.
    TimedOut,
}

/// Represents the logic needed to establish a connection over some transport.
/// See [crate::chat::http::ChatOverHttp2ServiceConnector]
/// and [crate::chat::ws::ChatOverWebSocketServiceConnector]
#[async_trait]
pub trait ServiceConnector: Clone {
    type Service;
    type Channel;
    type Error;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::Error>;

    fn start_service(&self, channel: Self::Channel) -> (Self::Service, ServiceStatus<Self::Error>);
}

#[async_trait]
impl<T> ServiceConnector for &'_ T
where
    T: ServiceConnector + Sync,
{
    type Service = T::Service;
    type Channel = T::Channel;
    type Error = T::Error;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::Error> {
        (*self).connect_channel(connection_params).await
    }

    fn start_service(&self, channel: Self::Channel) -> (Self::Service, ServiceStatus<Self::Error>) {
        (*self).start_service(channel)
    }
}

#[derive(Clone)]
pub struct ServiceConnectorWithDecorator<C> {
    inner: C,
    decorator: HttpRequestDecorator,
}

impl<C: ServiceConnector> ServiceConnectorWithDecorator<C> {
    pub fn new(inner: C, decorator: HttpRequestDecorator) -> Self {
        Self { inner, decorator }
    }
}

#[async_trait]
impl<'a, C> ServiceConnector for ServiceConnectorWithDecorator<C>
where
    C: ServiceConnector + Send + Sync + 'a,
{
    type Service = C::Service;
    type Channel = C::Channel;
    type Error = C::Error;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::Error> {
        let decorated = connection_params
            .clone()
            .with_decorator(self.decorator.clone());
        self.inner.connect_channel(&decorated).await
    }

    fn start_service(&self, channel: Self::Channel) -> (Self::Service, ServiceStatus<Self::Error>) {
        self.inner.start_service(channel)
    }
}

#[derive(Debug)]
#[derive_where(Clone)]
pub struct ServiceStatus<E> {
    maybe_error: Arc<OnceLock<E>>,
    service_cancellation: CancellationToken,
}

impl<E> ServiceStatus<E> {
    pub fn new() -> Self {
        Self {
            maybe_error: Arc::new(OnceLock::new()),
            service_cancellation: CancellationToken::new(),
        }
    }

    pub fn stop_service(&self) {
        self.service_cancellation.cancel();
    }

    pub fn stop_service_with_error(&self, error: E) {
        self.stop_service();
        self.maybe_error.get_or_init(|| error);
    }

    pub fn is_stopped(&self) -> bool {
        self.service_cancellation.is_cancelled()
    }

    pub async fn stopped(&self) {
        self.service_cancellation.cancelled().await
    }

    pub fn get_error(&self) -> Option<&E> {
        self.maybe_error.get()
    }
}

pub struct ServiceInitializer<C, M> {
    service_connector: C,
    connection_manager: M,
}

impl<'a, C, M> ServiceInitializer<C, M>
where
    M: ConnectionManager + 'a,
    C: ServiceConnector + Send + Sync + 'a,
    C::Service: Send + Sync + 'a,
    C::Channel: Send + Sync,
    C::Error: Send + Sync + Debug + LogSafeDisplay,
{
    pub fn new(service_connector: C, connection_manager: M) -> Self {
        Self {
            service_connector,
            connection_manager,
        }
    }

    pub async fn connect(&self) -> ServiceState<C::Service, C::Error> {
        log::debug!("attempting a connection");
        let connection_attempt_result = self
            .connection_manager
            .connect_or_wait(|connection_params| {
                log::debug!(
                    "trying to connect to {}:{}",
                    connection_params.host,
                    connection_params.port
                );
                self.service_connector.connect_channel(connection_params)
            })
            .await;

        match connection_attempt_result {
            ConnectionAttemptOutcome::Attempted(Ok(channel)) => {
                log::debug!("connection attempt succeeded");
                let (service, service_status) = self.service_connector.start_service(channel);
                ServiceState::Active(service, service_status)
            }
            ConnectionAttemptOutcome::Attempted(Err(e)) => {
                log::debug!("connection attempt failed due to an error: {:?}", e);
                ServiceState::Error(e)
            }
            ConnectionAttemptOutcome::WaitUntil(i) => {
                log::debug!(
                    "connection will not be attempted for another {} seconds",
                    i.duration_since(Instant::now()).as_secs()
                );
                ServiceState::Cooldown(i)
            }
            ConnectionAttemptOutcome::TimedOut => {
                log::debug!("connection attempt timed out");
                ServiceState::TimedOut
            }
        }
    }
}

struct ServiceWithReconnectData<C: ServiceConnector, M> {
    state: Mutex<ServiceState<C::Service, C::Error>>,
    service_initializer: ServiceInitializer<C, M>,
    connection_timeout: Duration,
}

#[derive(Clone)]
pub struct ServiceWithReconnect<C: ServiceConnector, M> {
    data: Arc<ServiceWithReconnectData<C, M>>,
}

impl<C, M> ServiceWithReconnect<C, M>
where
    M: ConnectionManager + 'static,
    C: ServiceConnector + Send + Sync + 'static,
    C::Service: Clone + Send + Sync + 'static,
    C::Channel: Send + Sync,
    C::Error: Send + Sync + Debug + LogSafeDisplay,
{
    pub fn new(service_connector: C, connection_manager: M, connection_timeout: Duration) -> Self {
        // We're starting in a `Cooldown` state with a `next_attempt_time` set to `now`,
        // which effectively allows for an immediate use.
        Self {
            data: Arc::new(ServiceWithReconnectData {
                state: Mutex::new(ServiceState::Cooldown(Instant::now())),
                service_initializer: ServiceInitializer::new(service_connector, connection_manager),
                connection_timeout,
            }),
        }
    }

    pub(crate) async fn service_clone(&self) -> Option<C::Service> {
        let deadline = Instant::now() + self.data.connection_timeout;
        let mut guard = match timeout_at(deadline, self.data.state.lock()).await {
            Ok(guard) => guard,
            Err(_) => {
                log::info!("Timed out waiting for the state lock");
                return None;
            }
        };
        loop {
            match &*guard {
                ServiceState::Active(service, service_status) => {
                    if !service_status.is_stopped() {
                        // if the state is `Active` and service has not been stopped,
                        // clone the service and return it
                        log::debug!("reusing active service instance");
                        return Some(service.clone());
                    }
                    if let Some(error) = service_status.get_error() {
                        log::debug!("Service stopped due to an error: {:?}", error);
                        log::info!("Service stopped due to an error: {}", error);
                    }
                }
                ServiceState::Cooldown(next_attempt_time) => {
                    // checking if the `next_attempt_time` is still in the future
                    if next_attempt_time > &deadline {
                        log::debug!("All possible routes are in cooldown state");
                        return None;
                    }
                    // it's safe to sleep without a `timeout`
                    // because we just checked that we'll wake before the deadline
                    tokio::time::sleep_until(*next_attempt_time).await;
                }
                ServiceState::TimedOut => {
                    // keep trying until we hit our own timeout deadline
                    log::info!("Connection attempt timed out");
                    if Instant::now() >= deadline {
                        return None;
                    }
                }
                ServiceState::Error(e) => {
                    // short circuiting mechanism is responsibility of the `ConnectionManager`,
                    // so here we're just going to keep trying until we get into
                    // one of the non-retryable states, `Cooldown` or time out.
                    log::info!("Connection attempt resulted in an error: {}", e);
                }
            };
            *guard = match timeout_at(deadline, self.data.service_initializer.connect()).await {
                Ok(result) => result,
                Err(_) => ServiceState::TimedOut,
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::fmt::Debug;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use futures_util::FutureExt;
    use tokio::time;
    use tokio::time::Instant;

    use crate::infra::certs::RootCertificates;
    use crate::infra::connection_manager::{
        SingleRouteThrottlingConnectionManager, MAX_COOLDOWN_INTERVAL,
    };
    use crate::infra::dns::DnsResolver;
    use crate::infra::reconnect::{
        ServiceConnector, ServiceState, ServiceStatus, ServiceWithReconnect,
    };
    use crate::infra::test::shared::{
        TestError, LONG_CONNECTION_TIME, NORMAL_CONNECTION_TIME, TIMEOUT_DURATION,
        TIME_ADVANCE_VALUE,
    };
    use crate::infra::{ConnectionParams, HttpRequestDecoratorSeq};

    #[derive(Clone, Debug)]
    struct TestService {
        service_status: ServiceStatus<TestError>,
    }

    impl TestService {
        fn new(service_status: ServiceStatus<TestError>) -> Self {
            Self { service_status }
        }

        fn close_channel(&self) {
            self.service_status.stop_service();
        }
    }

    #[derive(Clone)]
    struct TestServiceConnector {
        attempts: Arc<AtomicI32>,
        time_to_connect: Arc<Mutex<Duration>>,
        service_healthy: Arc<AtomicBool>,
    }

    impl TestServiceConnector {
        fn new() -> Self {
            Self {
                attempts: Arc::new(AtomicI32::new(0)),
                time_to_connect: Arc::new(Mutex::new(NORMAL_CONNECTION_TIME)),
                service_healthy: Arc::new(AtomicBool::new(true)),
            }
        }

        fn attempts_made(&self) -> i32 {
            self.attempts.fetch_or(0, Ordering::Relaxed)
        }

        fn set_time_to_connect(&self, time_to_connect: Duration) {
            let mut guard = self.time_to_connect.lock().unwrap();
            *guard = time_to_connect;
        }

        fn set_service_healthy(&self, service_healthy: bool) {
            self.service_healthy
                .store(service_healthy, Ordering::Relaxed);
        }
    }

    #[async_trait]
    impl ServiceConnector for TestServiceConnector {
        type Service = TestService;
        type Channel = ();
        type Error = TestError;

        async fn connect_channel(
            &self,
            _connection_params: &ConnectionParams,
        ) -> Result<Self::Channel, Self::Error> {
            self.attempts.fetch_add(1, Ordering::Relaxed);
            let connection_time = *self.time_to_connect.lock().unwrap();
            let service_healthy = self.service_healthy.load(Ordering::Relaxed);
            tokio::time::sleep(connection_time).await;
            if service_healthy {
                Ok(())
            } else {
                Err(TestError::Expected)
            }
        }

        fn start_service(
            &self,
            _channel: Self::Channel,
        ) -> (Self::Service, ServiceStatus<Self::Error>) {
            let service_status_arc = ServiceStatus::new();
            let service = TestService::new(service_status_arc.clone());
            (service, service_status_arc)
        }
    }

    fn example_connection_params() -> ConnectionParams {
        ConnectionParams::new(
            "chat.signal.org",
            "chat.signal.org",
            443,
            HttpRequestDecoratorSeq::default(),
            RootCertificates::Signal,
            DnsResolver::System,
        )
    }

    #[tokio::test]
    async fn service_not_started_before_first_request() {
        let connector = TestServiceConnector::new();
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(),
            TIMEOUT_DURATION,
        );
        let _ = ServiceWithReconnect::new(connector.clone(), manager, TIMEOUT_DURATION);
        assert_eq!(connector.attempts_made(), 0);
    }

    #[tokio::test]
    async fn service_started_with_request() {
        let connector = TestServiceConnector::new();
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(),
            TIMEOUT_DURATION,
        );
        let service_with_reconnect =
            ServiceWithReconnect::new(connector.clone(), manager, TIMEOUT_DURATION);
        let _service = service_with_reconnect.service_clone().await;
        assert_eq!(connector.attempts_made(), 1);
    }

    #[tokio::test]
    async fn moving_to_inactive_on_channel_closed() {
        let connector = TestServiceConnector::new();
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(),
            TIMEOUT_DURATION,
        );
        let service_with_reconnect =
            ServiceWithReconnect::new(connector.clone(), manager, TIMEOUT_DURATION);
        let service = service_with_reconnect.service_clone().await;

        assert_matches!(
            *service_with_reconnect.data.state.lock().await,
            ServiceState::Active(_, ref status) if !status.is_stopped()
        );

        service.expect("service is present").close_channel();

        assert_matches!(
            *service_with_reconnect.data.state.lock().await,
            ServiceState::Active(_, ref status) if status.is_stopped()
        );
    }

    #[tokio::test]
    async fn immediately_fail_if_in_cooldown() {
        let connector = TestServiceConnector::new();
        connector.set_service_healthy(false);

        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(),
            TIMEOUT_DURATION,
        );
        let service_with_reconnect =
            ServiceWithReconnect::new(connector.clone(), manager, TIMEOUT_DURATION);
        let service = service_with_reconnect.service_clone().await;
        assert!(service.is_none());
        assert!(connector.attempts_made() > 1);
        assert_matches!(
            *service_with_reconnect.data.state.lock().await,
            ServiceState::Cooldown(_)
        );

        let now_or_never_service_option = service_with_reconnect.service_clone().now_or_never();
        // the future should be completed immediately
        // but the result of the future should be `None` because we're in cooldown
        assert!(now_or_never_service_option
            .expect("completed future")
            .is_none());
    }

    #[tokio::test]
    async fn retry_connection_after_service_disconnected() {
        let connector = TestServiceConnector::new();
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(),
            TIMEOUT_DURATION,
        );
        let service_with_reconnect =
            ServiceWithReconnect::new(connector.clone(), manager, TIMEOUT_DURATION);
        let service = service_with_reconnect.service_clone().await;
        service.expect("service is present").close_channel();
        let service = service_with_reconnect.service_clone().await;
        assert_eq!(connector.attempts_made(), 2);
        assert!(service.is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multiple_callers_single_attempt() {
        let connector = TestServiceConnector::new();
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(),
            TIMEOUT_DURATION,
        );
        let service_with_reconnect =
            ServiceWithReconnect::new(connector.clone(), manager, TIMEOUT_DURATION);

        let aaa1 = service_with_reconnect.clone();
        let handle1 = tokio::spawn(async move { aaa1.service_clone().await });

        let aaa2 = service_with_reconnect.clone();
        let handle2 = tokio::spawn(async move { aaa2.service_clone().await });

        let (s1, s2) = tokio::join!(handle1, handle2);
        assert!(s1.expect("future completed successfully").is_some());
        assert!(s2.expect("future completed successfully").is_some());
        assert_eq!(connector.attempts_made(), 1);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn service_returns_if_connection_keeps_timing_out() {
        let start = Instant::now();
        let connection_time = LONG_CONNECTION_TIME;
        let connection_timeout = TIMEOUT_DURATION;
        let service_with_reconnect_timeout = TIMEOUT_DURATION * 2;

        let connector = TestServiceConnector::new();
        connector.set_time_to_connect(connection_time);
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(),
            connection_timeout,
        );
        let service_with_reconnect =
            ServiceWithReconnect::new(connector.clone(), manager, service_with_reconnect_timeout);
        let res = service_with_reconnect.service_clone().await;

        // now the time should've auto-advanced from `start` by the `connection_timeout` value
        assert!(res.is_none());
        assert_eq!(Instant::now(), start + service_with_reconnect_timeout);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn service_returns_if_connection_time_exceeds_its_own_timeout() {
        let start = Instant::now();
        let connection_time = LONG_CONNECTION_TIME;
        let connection_timeout = TIMEOUT_DURATION * 2;
        let service_with_reconnect_timeout = TIMEOUT_DURATION;

        let connector = TestServiceConnector::new();
        connector.set_time_to_connect(connection_time);

        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(),
            connection_timeout,
        );
        let service_with_reconnect =
            ServiceWithReconnect::new(connector.clone(), manager, service_with_reconnect_timeout);
        let res = service_with_reconnect.service_clone().await;

        // now the time should've auto-advanced from `start` by the `connection_timeout` value
        assert!(res.is_none());
        assert_eq!(Instant::now(), start + service_with_reconnect_timeout);
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn service_able_to_connect_after_failed_attempt() {
        let connector = TestServiceConnector::new();
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(),
            TIMEOUT_DURATION,
        );
        let service_with_reconnect =
            ServiceWithReconnect::new(connector.clone(), manager, TIMEOUT_DURATION);

        time::advance(TIME_ADVANCE_VALUE).await;
        connector.set_service_healthy(false);
        let service = service_with_reconnect.service_clone().await;
        assert!(service.is_none());

        // At this point, `service_with_reconnect` tried multiple times to connect
        // and hit the cooldown. Let's advance time to make sure next attempt will be made.
        time::advance(MAX_COOLDOWN_INTERVAL).await;

        connector.set_service_healthy(true);
        let service = service_with_reconnect.service_clone().await;
        assert!(service.is_some());
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn service_able_to_connect_after_timed_out_attempt() {
        let connector = TestServiceConnector::new();
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(),
            TIMEOUT_DURATION,
        );
        let service_with_reconnect =
            ServiceWithReconnect::new(connector.clone(), manager, TIMEOUT_DURATION);

        time::advance(TIME_ADVANCE_VALUE).await;
        connector.set_time_to_connect(LONG_CONNECTION_TIME);
        let service = service_with_reconnect.service_clone().await;
        assert!(service.is_none());

        // At this point, `service_with_reconnect` tried multiple times to connect
        // and hit the cooldown. Let's advance time to make sure next attempt will be made.
        time::advance(MAX_COOLDOWN_INTERVAL).await;

        connector.set_time_to_connect(NORMAL_CONNECTION_TIME);
        let service = service_with_reconnect.service_clone().await;
        assert!(service.is_some());
    }
}
