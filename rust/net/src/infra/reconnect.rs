//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use crate::chat::RemoteAddressInfo;
use async_trait::async_trait;
use derive_where::derive_where;
use displaydoc::Display;
use tokio::sync::Mutex;
use tokio::time::{timeout_at, Instant};
use tokio_util::sync::CancellationToken;

use crate::infra::connection_manager::{ConnectionAttemptOutcome, ConnectionManager};
use crate::infra::errors::LogSafeDisplay;
use crate::infra::{ConnectionInfo, ConnectionParams, HttpRequestDecorator};

/// For a service that needs to go through some initialization procedure
/// before it's ready for use, this enum describes its possible states.
#[derive(Debug)]
pub(crate) enum ServiceState<T, CE, SE> {
    /// Service was not explicitly activated.
    Inactive,
    /// Contains an instance of the service which is initialized and ready to use.
    /// Also, since we're not actively listening for the event of service going inactive,
    /// the `ServiceStatus` could be used to see if the service is actually running.
    Active(T, ServiceStatus<SE>),
    /// The service is inactive and no initialization attempts are to be made
    /// until the `Instant` held by this object.
    Cooldown(Instant),
    /// Last connection attempt resulted in an error.
    Error(CE),
    /// Last connection attempt timed out.
    ConnectionTimedOut,
}

/// Represents the logic needed to establish a connection over some transport.
/// See [crate::chat::http::ChatOverHttp2ServiceConnector]
/// and [crate::chat::ws::ChatOverWebSocketServiceConnector]
#[async_trait]
pub(crate) trait ServiceConnector: Clone {
    type Service;
    type Channel;
    type ConnectError;
    type StartError;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::ConnectError>;

    fn start_service(
        &self,
        channel: Self::Channel,
    ) -> (Self::Service, ServiceStatus<Self::StartError>);
}

#[async_trait]
impl<T> ServiceConnector for &'_ T
where
    T: ServiceConnector + Sync,
{
    type Service = T::Service;
    type Channel = T::Channel;
    type ConnectError = T::ConnectError;
    type StartError = T::StartError;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::ConnectError> {
        (*self).connect_channel(connection_params).await
    }

    fn start_service(
        &self,
        channel: Self::Channel,
    ) -> (Self::Service, ServiceStatus<Self::StartError>) {
        (*self).start_service(channel)
    }
}

#[derive(Clone)]
pub(crate) struct ServiceConnectorWithDecorator<C> {
    inner: C,
    decorator: HttpRequestDecorator,
}

impl<C: ServiceConnector> ServiceConnectorWithDecorator<C> {
    pub(crate) fn new(inner: C, decorator: HttpRequestDecorator) -> Self {
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
    type ConnectError = C::ConnectError;
    type StartError = C::StartError;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::ConnectError> {
        let decorated = connection_params
            .clone()
            .with_decorator(self.decorator.clone());
        self.inner.connect_channel(&decorated).await
    }

    fn start_service(
        &self,
        channel: Self::Channel,
    ) -> (Self::Service, ServiceStatus<Self::StartError>) {
        self.inner.start_service(channel)
    }
}

#[derive(Debug)]
#[derive_where(Clone)]
pub(crate) struct ServiceStatus<E> {
    maybe_error: Arc<OnceLock<E>>,
    service_cancellation: CancellationToken,
}

impl<E> Default for ServiceStatus<E> {
    fn default() -> Self {
        Self {
            maybe_error: Arc::new(OnceLock::new()),
            service_cancellation: CancellationToken::new(),
        }
    }
}

impl<E> ServiceStatus<E> {
    pub(crate) fn stop_service(&self) {
        self.service_cancellation.cancel();
    }

    pub(crate) fn stop_service_with_error(&self, error: E) {
        self.maybe_error.get_or_init(|| error);
        self.stop_service();
    }

    pub(crate) fn is_stopped(&self) -> bool {
        self.service_cancellation.is_cancelled()
    }

    pub(crate) async fn stopped(&self) {
        self.service_cancellation.cancelled().await
    }

    pub(crate) fn get_error(&self) -> Option<&E> {
        self.maybe_error.get()
    }
}

pub(crate) struct ServiceInitializer<C, M> {
    service_connector: C,
    connection_manager: M,
}

impl<'a, C, M> ServiceInitializer<C, M>
where
    M: ConnectionManager + 'a,
    C: ServiceConnector + Send + Sync + 'a,
    C::Service: Send + Sync + 'a,
    C::Channel: Send + Sync,
    C::ConnectError: Send + Sync + Debug + LogSafeDisplay,
{
    pub(crate) fn new(service_connector: C, connection_manager: M) -> Self {
        Self {
            service_connector,
            connection_manager,
        }
    }

    pub(crate) async fn connect(&self) -> ServiceState<C::Service, C::ConnectError, C::StartError> {
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
                ServiceState::ConnectionTimedOut
            }
        }
    }
}

pub(crate) struct ServiceWithReconnectData<C: ServiceConnector, M> {
    reconnect_count: AtomicU32,
    state: Mutex<ServiceState<C::Service, C::ConnectError, C::StartError>>,
    service_initializer: ServiceInitializer<C, M>,
    connection_timeout: Duration,
}

#[derive(Clone)]
pub(crate) struct ServiceWithReconnect<C: ServiceConnector, M> {
    data: Arc<ServiceWithReconnectData<C, M>>,
}

#[derive(Debug, Display)]
pub(crate) enum ReconnectError {
    /// Operation timed out
    Timeout { attempts: u16 },
    /// All attempted routes failed to connect
    AllRoutesFailed { attempts: u16 },
    /// Service is in the inactive state
    Inactive,
}

#[derive(Debug, Display)]
pub(crate) enum StateError {
    /// Service is in the inactive state
    Inactive,
    /// Service is unavailable due to the lost connection
    ServiceUnavailable,
}

impl<C, M> ServiceWithReconnect<C, M>
where
    C: ServiceConnector,
{
    async fn map_service<T>(&self, mapper: fn(&C::Service) -> T) -> Result<T, StateError> {
        let guard = self.data.state.lock().await;
        match &*guard {
            ServiceState::Active(service, status) if !status.is_stopped() => Ok(mapper(service)),
            ServiceState::Inactive => Err(StateError::Inactive),
            ServiceState::Cooldown(_)
            | ServiceState::ConnectionTimedOut
            | ServiceState::Error(_)
            | ServiceState::Active(_, _) => Err(StateError::ServiceUnavailable),
        }
    }
}

impl<C, M> ServiceWithReconnect<C, M>
where
    C: ServiceConnector,
    C::Service: RemoteAddressInfo,
{
    pub(crate) async fn connection_info(&self) -> Result<ConnectionInfo, StateError> {
        self.map_service(|s| s.connection_info().clone()).await
    }
}

impl<C, M> ServiceWithReconnect<C, M>
where
    M: ConnectionManager + 'static,
    C: ServiceConnector + Send + Sync + 'static,
    C::Service: Clone + Send + Sync + 'static,
    C::Channel: Send + Sync,
    C::ConnectError: Send + Sync + Debug + LogSafeDisplay,
    C::StartError: Send + Sync + Debug + LogSafeDisplay,
{
    pub(crate) fn new(
        service_connector: C,
        connection_manager: M,
        connection_timeout: Duration,
    ) -> Self {
        Self {
            data: Arc::new(ServiceWithReconnectData {
                state: Mutex::new(ServiceState::Inactive),
                service_initializer: ServiceInitializer::new(service_connector, connection_manager),
                connection_timeout,
                reconnect_count: AtomicU32::new(0),
            }),
        }
    }

    pub(crate) fn reconnect_count(&self) -> u32 {
        self.data.reconnect_count.load(Ordering::Relaxed)
    }

    pub(crate) async fn reconnect_if_active(&self) -> Result<(), ReconnectError> {
        self.connect(true).await
    }

    pub(crate) async fn connect_from_inactive(&self) -> Result<(), ReconnectError> {
        self.connect(false).await
    }

    async fn connect(&self, respect_inactive: bool) -> Result<(), ReconnectError> {
        let mut attempts: u16 = 0;
        let start_of_connection_process = Instant::now();
        let deadline = start_of_connection_process + self.data.connection_timeout;
        let mut guard = match timeout_at(deadline, self.data.state.lock()).await {
            Ok(guard) => guard,
            Err(_) => {
                log::info!("Timed out waiting for the state lock");
                return Err(ReconnectError::Timeout { attempts });
            }
        };
        let lock_taken_instant = Instant::now();
        loop {
            match &*guard {
                ServiceState::Inactive => {
                    if respect_inactive {
                        return Err(ReconnectError::Inactive);
                    }
                    // otherwise, proceeding to connect
                }
                ServiceState::Active(_, service_status) => {
                    if !service_status.is_stopped() {
                        // if the state is `Active` and service has not been stopped,
                        // clone the service and return it
                        log::debug!("reusing active service instance");
                        return Ok(());
                    }
                }
                ServiceState::Cooldown(next_attempt_time) => {
                    // checking if the `next_attempt_time` is still in the future
                    if next_attempt_time > &deadline {
                        log::debug!("All possible routes are in cooldown state");
                        return Err(ReconnectError::AllRoutesFailed { attempts });
                    }
                    // it's safe to sleep without a `timeout`
                    // because we just checked that we'll wake before the deadline
                    tokio::time::sleep_until(*next_attempt_time).await;
                }
                ServiceState::ConnectionTimedOut => {
                    // Only log about timeouts that happened on *this* connect attempt.
                    match attempts {
                        0 => {}
                        1 => {
                            log::info!(
                                "Connection attempt timed out ({:.2?} spent waiting for lock)",
                                lock_taken_instant.duration_since(start_of_connection_process)
                            );
                        }
                        _ => {
                            log::info!("Connection attempt timed out");
                        }
                    }
                    // keep trying until we hit our own timeout deadline
                    if Instant::now() >= deadline {
                        return Err(ReconnectError::Timeout { attempts });
                    }
                }
                ServiceState::Error(e) => {
                    // short-circuiting mechanism is responsibility of the `ConnectionManager`,
                    // so here we're just going to keep trying until we get into
                    // one of the non-retryable states, `Cooldown` or time out.
                    if attempts > 0 {
                        // Only log about errors that happened on *this* connect attempt.
                        log::info!("Connection attempt resulted in an error: {}", e);
                    }
                }
            };
            attempts += 1;
            *guard = match timeout_at(deadline, self.data.service_initializer.connect()).await {
                Ok(ServiceState::Active(service, service_state)) => {
                    self.schedule_reconnect(service_state.clone());
                    ServiceState::Active(service, service_state)
                }
                Ok(result) => result,
                Err(_) => ServiceState::ConnectionTimedOut,
            }
        }
    }

    pub(crate) async fn disconnect(&self) {
        let mut guard = self.data.state.lock().await;
        if let ServiceState::Active(_, service_status) = &*guard {
            service_status.stop_service();
        }
        *guard = ServiceState::Inactive;
        log::info!("service disconnected");
    }

    pub(crate) async fn service(&self) -> Result<C::Service, StateError> {
        self.map_service(|service| service.clone()).await
    }

    fn schedule_reconnect(&self, service_status: ServiceStatus<C::StartError>) {
        let service_with_reconnect = self.clone();
        tokio::spawn(async move {
            let _ = service_status.service_cancellation.cancelled().await;
            if let Some(error) = service_status.get_error() {
                log::debug!("Service stopped due to an error: {:?}", error);
                log::info!("Service stopped due to an error: {}", error);
            } else {
                log::info!("Service stopped");
            }
            // This is a background thread so there is no overall timeout on reconnect.
            // Each attempt is limited by the `data.connection_timeout` duration
            // but unless we're in one of the non-proceeding states, we'll be trying to
            // connect.
            let mut sleep_until = Instant::now();
            loop {
                if sleep_until > Instant::now() {
                    tokio::time::sleep_until(sleep_until).await;
                }
                log::info!("attempting reconnect");
                match service_with_reconnect.reconnect_if_active().await {
                    Ok(_) => {
                        log::info!("reconnect attempt succeeded");
                        service_with_reconnect
                            .data
                            .reconnect_count
                            .fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    Err(error) => {
                        log::warn!("reconnect attempt failed: {}", error);
                        let guard = service_with_reconnect.data.state.lock().await;
                        match &*guard {
                            ServiceState::Cooldown(next_attempt_time) => {
                                sleep_until = *next_attempt_time;
                            }
                            ServiceState::ConnectionTimedOut | ServiceState::Error(_) => {
                                // keep trying
                            }
                            ServiceState::Inactive | ServiceState::Active(_, _) => {
                                // most likely, `disconnect()` was called and we
                                // switched to the `ServiceState::Inactive` state
                                return;
                            }
                        }
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod test {
    use std::fmt::Debug;
    use std::future::Future;
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use futures_util::FutureExt;
    use nonzero_ext::nonzero;
    use tokio::time;
    use tokio::time::Instant;

    use crate::infra::certs::RootCertificates;
    use crate::infra::connection_manager::{
        SingleRouteThrottlingConnectionManager, COOLDOWN_INTERVALS, MAX_COOLDOWN_INTERVAL,
    };
    use crate::infra::reconnect::{
        ReconnectError, ServiceConnector, ServiceState, ServiceStatus, ServiceWithReconnect,
        StateError,
    };
    use crate::infra::test::shared::{
        TestError, LONG_CONNECTION_TIME, NORMAL_CONNECTION_TIME, TIMEOUT_DURATION,
        TIME_ADVANCE_VALUE,
    };
    use crate::infra::{ConnectionParams, HttpRequestDecoratorSeq, RouteType};

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
        type ConnectError = TestError;
        type StartError = TestError;

        async fn connect_channel(
            &self,
            _connection_params: &ConnectionParams,
        ) -> Result<Self::Channel, Self::ConnectError> {
            let connection_time = *self.time_to_connect.lock().unwrap();
            let service_healthy = self.service_healthy.load(Ordering::Relaxed);
            tokio::time::sleep(connection_time).await;
            self.attempts.fetch_add(1, Ordering::Relaxed);
            if service_healthy {
                Ok(())
            } else {
                Err(TestError::Expected)
            }
        }

        fn start_service(
            &self,
            _channel: Self::Channel,
        ) -> (Self::Service, ServiceStatus<Self::StartError>) {
            let service_status_arc = ServiceStatus::default();
            let service = TestService::new(service_status_arc.clone());
            (service, service_status_arc)
        }
    }

    fn example_connection_params() -> ConnectionParams {
        ConnectionParams::new(
            RouteType::Test,
            "chat.signal.org",
            "chat.signal.org",
            nonzero!(443u16),
            HttpRequestDecoratorSeq::default(),
            RootCertificates::Signal,
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
        let (connector, service_with_reconnect) = connector_and_service();
        service_with_reconnect
            .connect_from_inactive()
            .await
            .expect("");
        let _service = service_with_reconnect.service().await;
        assert_eq!(connector.attempts_made(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn service_tries_to_reconnect_if_connection_lost() {
        let (connector, service_with_reconnect) = connector_and_service();
        service_with_reconnect
            .connect_from_inactive()
            .await
            .expect("connected");

        let service = service_with_reconnect.service().await.expect("available");

        // `close_channel()` call emulates lost connection and reconnection will be triggered
        // unless service_with_reconnect is in the `Inactive` state
        service.close_channel();

        // giving time to reconnect
        sleep_and_catch_up(NORMAL_CONNECTION_TIME).await;

        let service = service_with_reconnect.service().await.expect("available");

        // we're doing it again, but this time we'll instruct service connector to fail,
        // and as a result, service won't be available
        service.close_channel();
        connector.set_service_healthy(false);
        time::advance(TIME_ADVANCE_VALUE).await;

        assert_matches!(
            service_with_reconnect.service().await,
            Err(StateError::ServiceUnavailable)
        );
    }

    #[tokio::test]
    async fn service_is_inactive_before_connected() {
        let (_, service_with_reconnect) = connector_and_service();
        assert_matches!(
            service_with_reconnect.service().await,
            Err(StateError::Inactive)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn service_doesnt_reconnect_if_disconnected() {
        let (_, service_with_reconnect) = connector_and_service();
        service_with_reconnect
            .connect_from_inactive()
            .await
            .expect("connected");

        // making sure service is available
        let _ = service_with_reconnect.service().await.expect("available");

        service_with_reconnect.disconnect().await;

        // advancing time to make sure that reconnect logic is executed and doesn't reconnect
        time::advance(TIME_ADVANCE_VALUE).await;

        // now when we're trying to get the service, it should be in `Inactive` state
        assert_matches!(
            service_with_reconnect.service().await,
            Err(StateError::Inactive)
        );
    }

    #[tokio::test]
    async fn immediately_fail_if_in_cooldown() {
        let (connector, service_with_reconnect) = connector_and_service();

        connector.set_service_healthy(false);
        let connection_result = service_with_reconnect.connect_from_inactive().await;

        // Here we have 3 attempts made by the reconnect service:
        // - first attempt went to the connector and resulted in expected error
        // - after the first attempt, the configured cooldown is 0, so the second attempt
        //   also went to the connector and resulted in expected error
        // - after two consecutive unsuccessful attempts, the configured cooldown is 1 second,
        //   so the third attempt was made by the reconnect service but didn't reach the connector
        //   and immediately resulted in a Cooldown result
        // - 1 second is longder than our test TIMEOUT_DURATION, so no more attempts were made
        // Based on that, connector only saw 2 attempts, but ServiceWithReconnect had time
        // to perform 3 attempts.
        // Note that if the values in `COOLDOWN_INTERVALS` constant change, the number of attempts
        // may also change
        assert_eq!(connector.attempts_made(), 2);
        assert_matches!(
            connection_result,
            Err(ReconnectError::AllRoutesFailed { attempts: 3 })
        );

        assert_matches!(
            *service_with_reconnect.data.state.lock().await,
            ServiceState::Cooldown(_)
        );

        let now_or_never_service_option = service_with_reconnect.service().now_or_never();
        // the future should be completed immediately
        // but the result of the future should be `Err()` because we're in cooldown
        assert!(now_or_never_service_option
            .expect("completed future")
            .is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multiple_callers_single_attempt() {
        let (connector, service_with_reconnect) = connector_and_service();

        let aaa1 = service_with_reconnect.clone();
        let handle1 = tokio::spawn(async move { aaa1.connect_from_inactive().await });

        let aaa2 = service_with_reconnect.clone();
        let handle2 = tokio::spawn(async move { aaa2.connect_from_inactive().await });

        let (s1, s2) = tokio::join!(handle1, handle2);
        assert!(s1.expect("future completed successfully").is_ok());
        assert!(s2.expect("future completed successfully").is_ok());
        assert_eq!(connector.attempts_made(), 1);
    }

    #[tokio::test(start_paused = true)]
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
        let res = service_with_reconnect.connect_from_inactive().await;

        // now the time should've auto-advanced from `start` by the `connection_timeout` value
        assert!(res.is_err());
        assert_eq!(Instant::now(), start + service_with_reconnect_timeout);
    }

    #[tokio::test(start_paused = true)]
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
        let res = service_with_reconnect.connect_from_inactive().await;

        // now the time should've auto-advanced from `start` by the `connection_timeout` value
        assert_matches!(res, Err(ReconnectError::Timeout { attempts: 1 }));
        assert_eq!(Instant::now(), start + service_with_reconnect_timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn service_able_to_connect_after_failed_attempt() {
        let (connector, service_with_reconnect) = connector_and_service();

        time::advance(TIME_ADVANCE_VALUE).await;
        connector.set_service_healthy(false);
        let connection_result = service_with_reconnect.connect_from_inactive().await;

        // number of attempts is the same as in the `immediately_fail_if_in_cooldown()` test
        assert_matches!(
            connection_result,
            Err(ReconnectError::AllRoutesFailed { attempts: 3 })
        );

        // At this point, `service_with_reconnect` tried multiple times to connect
        // and hit the cooldown. Let's advance time to make sure next attempt will be made.
        time::advance(MAX_COOLDOWN_INTERVAL).await;

        connector.set_service_healthy(true);
        let connection_result = service_with_reconnect.connect_from_inactive().await;
        assert_matches!(connection_result, Ok(_));
    }

    #[tokio::test(start_paused = true)]
    async fn service_able_to_connect_after_timed_out_attempt() {
        let (connector, service_with_reconnect) = connector_and_service();
        time::advance(TIME_ADVANCE_VALUE).await;
        connector.set_time_to_connect(LONG_CONNECTION_TIME);
        let connection_result = service_with_reconnect.connect_from_inactive().await;
        assert_matches!(
            connection_result,
            Err(ReconnectError::Timeout { attempts: 1 })
        );

        // At this point, `service_with_reconnect` tried multiple times to connect
        // and hit the cooldown. Let's advance time to make sure next attempt will be made.
        time::advance(MAX_COOLDOWN_INTERVAL).await;

        connector.set_time_to_connect(NORMAL_CONNECTION_TIME);
        let connection_result = service_with_reconnect.connect_from_inactive().await;
        assert_matches!(connection_result, Ok(_));
    }

    #[tokio::test(start_paused = true)]
    async fn service_keep_reconnecting_attempts_if_first_fails() {
        let (connector, service_with_reconnect) = connector_and_service();
        service_with_reconnect
            .connect_from_inactive()
            .await
            .expect("connected");
        let service = service_with_reconnect.service().await.expect("service");

        // at this point, one successfull connection attempt
        assert_eq!(connector.attempts.load(Ordering::Relaxed), 1);

        // internet connection lost
        connector.set_service_healthy(false);
        service.close_channel();

        sleep_and_catch_up(NORMAL_CONNECTION_TIME).await;
        assert_eq!(connector.attempts.load(Ordering::Relaxed), 2);

        sleep_and_catch_up(COOLDOWN_INTERVALS[0] + NORMAL_CONNECTION_TIME).await;
        assert_eq!(connector.attempts.load(Ordering::Relaxed), 3);
        assert_matches!(service_with_reconnect.service().await, Err(_));

        sleep_and_catch_up(COOLDOWN_INTERVALS[1] + NORMAL_CONNECTION_TIME).await;
        assert_eq!(connector.attempts.load(Ordering::Relaxed), 4);
        assert_matches!(service_with_reconnect.service().await, Err(_));

        // now internet connection is back
        // letting next cooldown interval pass and checking again
        connector.set_service_healthy(true);

        sleep_and_catch_up(COOLDOWN_INTERVALS[2] + NORMAL_CONNECTION_TIME).await;
        assert_eq!(connector.attempts.load(Ordering::Relaxed), 5);
        assert_matches!(service_with_reconnect.service().await, Ok(_));
    }

    #[tokio::test(start_paused = true)]
    async fn service_stops_reconnect_attempts_if_disconnected_after_some_time() {
        let (connector, service_with_reconnect) = connector_and_service();
        service_with_reconnect
            .connect_from_inactive()
            .await
            .expect("connected");
        let service = service_with_reconnect.service().await.expect("service");

        // at this point, one successfull connection attempt
        assert_eq!(connector.attempts.load(Ordering::Relaxed), 1);

        // internet connection lost
        connector.set_service_healthy(false);
        service.close_channel();

        sleep_and_catch_up(NORMAL_CONNECTION_TIME).await;
        assert_eq!(connector.attempts.load(Ordering::Relaxed), 2);

        sleep_and_catch_up(COOLDOWN_INTERVALS[0] + NORMAL_CONNECTION_TIME).await;
        assert_eq!(connector.attempts.load(Ordering::Relaxed), 3);
        assert_matches!(service_with_reconnect.service().await, Err(_));

        sleep_and_catch_up(COOLDOWN_INTERVALS[1] + NORMAL_CONNECTION_TIME).await;
        assert_eq!(connector.attempts.load(Ordering::Relaxed), 4);
        assert_matches!(service_with_reconnect.service().await, Err(_));

        // now we decide to disconnect, and we need to make sure we're not making
        // any more attempts
        service_with_reconnect.disconnect().await;
        for interval in COOLDOWN_INTERVALS.into_iter().skip(2) {
            sleep_and_catch_up(interval + NORMAL_CONNECTION_TIME).await;
            assert_eq!(connector.attempts.load(Ordering::Relaxed), 4);
            assert_matches!(
                service_with_reconnect.service().await,
                Err(StateError::Inactive)
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_count_behaves_correctly() {
        let (_, service_with_reconnect) = connector_and_service();
        service_with_reconnect
            .connect_from_inactive()
            .await
            .expect("connected");
        let service = service_with_reconnect.service().await.expect("service");

        // manual connection should not count as "reconnect"
        assert_eq!(0, service_with_reconnect.reconnect_count());

        // emulating unexpected disconnect
        service.close_channel();
        // giving time to reconnect
        sleep_and_catch_up(NORMAL_CONNECTION_TIME).await;

        // reconnect count should increase by 1
        assert_eq!(1, service_with_reconnect.reconnect_count());

        // now, manually disconnecting and connecting again
        service_with_reconnect.disconnect().await;
        service_with_reconnect
            .connect_from_inactive()
            .await
            .expect("connected");

        // reconnect count should not change
        assert_eq!(1, service_with_reconnect.reconnect_count());
    }

    #[tokio::test(start_paused = true)]
    async fn sleep_and_catch_up_showcase() {
        const DURATION: Duration = Duration::from_millis(100);

        async fn test<F: Future<Output = ()>>(sleep_variant: F) -> bool {
            let flag = Arc::new(AtomicBool::new(false));
            let flag_clone = flag.clone();
            tokio::spawn(async move {
                time::sleep(DURATION).await;
                flag_clone.store(true, Ordering::Relaxed);
            });
            sleep_variant.await;
            flag.load(Ordering::Relaxed)
        }

        assert!(!test(time::sleep(DURATION)).await);
        assert!(!test(time::advance(DURATION)).await);
        assert!(test(sleep_and_catch_up(DURATION)).await);
    }

    async fn sleep_and_catch_up(duration: Duration) {
        // In the tokio time paused test mode, if some logic is supposed to wake up at specific time
        // and a test wants to make sure it observes the result of that logic without moving
        // the time past that point, it's not enough to call `sleep()` or `advance()` alone.
        // The combination of sleeping and advancing by 0 makes sure that all events
        // (in all tokio thread) scheduled to run at (or before) that specific time are processed.
        //
        // `sleep_and_catch_up_showcase()` test demonstrates this behavior.
        time::sleep(duration).await;
        time::advance(Duration::ZERO).await
    }

    fn connector_and_service() -> (
        TestServiceConnector,
        ServiceWithReconnect<TestServiceConnector, SingleRouteThrottlingConnectionManager>,
    ) {
        let connector = TestServiceConnector::new();
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(),
            TIMEOUT_DURATION,
        );
        let service_with_reconnect =
            ServiceWithReconnect::new(connector.clone(), manager, TIMEOUT_DURATION);
        (connector, service_with_reconnect)
    }
}
