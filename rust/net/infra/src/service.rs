//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use displaydoc::Display;
use tokio::sync::Mutex;
use tokio::time::{timeout_at, Instant};

use crate::connection_manager::{
    ConnectionAttemptOutcome, ConnectionManager, ErrorClass, ErrorClassifier,
};
use crate::errors::LogSafeDisplay;
use crate::{ConnectionParams, HttpRequestDecorator, ServiceConnectionInfo};

// A duration where, if this is all that's left on the timeout, we're more likely to fail than not.
// Useful for debouncing repeated connection attempts.
const MINIMUM_CONNECTION_TIME: Duration = Duration::from_millis(500);

/// For a service that needs to go through some initialization procedure
/// before it's ready for use, this enum describes its possible states.
#[derive(Debug)]
pub enum ServiceState<T, CE> {
    /// Service was not explicitly activated.
    Inactive,
    /// Contains an instance of the service which is initialized and ready to use.
    /// Also, since we're not actively listening for the event of service going inactive,
    /// the `CancellationToken` could be used to see if the service is actually running.
    Active(T, CancellationToken),
    /// The service is inactive and no initialization attempts are to be made
    /// until the `Instant` held by this object.
    Cooldown(Instant),
    /// Last connection attempt resulted in an error.
    Error(CE),
    /// Last connection attempt timed out.
    ConnectionTimedOut,
}

mod cancel_token;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CancellationReason {
    ExplicitDisconnect,
    ServiceError,
    RemoteClose,
    ProtocolError,
}

pub type CancellationToken = cancel_token::CancellationToken<CancellationReason>;

pub trait RemoteAddressInfo {
    /// Provides information about the remote address the service is connected to
    fn connection_info(&self) -> ServiceConnectionInfo;
}

/// Creates connections to a "service" representing a remote resource accessible over HTTPS.
///
/// Implementers split the creation of a connection into two phases:
/// 1. creating a channel to the remote resource.
/// 2. creating a local "service" for the remote resource.
///
/// Once the channel is established, creating the service is an infallible
/// operation. Requests or queries sent to the service can still fail later, but
/// the service is guaranteed to exist.
#[async_trait]
pub trait ServiceConnector: Clone {
    type Service;
    type Channel;
    type ConnectError;

    /// Attempts to establish a channel to the given remote resource.
    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::ConnectError>;

    /// Creates a local "service" that interacts with the resource at the end of
    /// the channel.
    ///
    /// The returned service can be destroyed by cancelling it with the returned
    /// [`CancellationToken`].
    fn start_service(&self, channel: Self::Channel) -> (Self::Service, CancellationToken);
}

#[async_trait]
impl<T> ServiceConnector for &'_ T
where
    T: ServiceConnector + Sync,
{
    type Service = T::Service;
    type Channel = T::Channel;
    type ConnectError = T::ConnectError;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::ConnectError> {
        (*self).connect_channel(connection_params).await
    }

    fn start_service(&self, channel: Self::Channel) -> (Self::Service, CancellationToken) {
        (*self).start_service(channel)
    }
}

/// [`ServiceConnector`] implementation that decorates all outgoing requests.
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
impl<C> ServiceConnector for ServiceConnectorWithDecorator<C>
where
    C: ServiceConnector + Send + Sync,
{
    type Service = C::Service;
    type Channel = C::Channel;
    type ConnectError = C::ConnectError;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::ConnectError> {
        let decorated = connection_params
            .clone()
            .with_decorator(self.decorator.clone());
        self.inner.connect_channel(&decorated).await
    }

    fn start_service(&self, channel: Self::Channel) -> (Self::Service, CancellationToken) {
        self.inner.start_service(channel)
    }
}

/// Describes a remote resource and how to attempt to connect to it.
///
/// Combines a [`ConnectionManager`] and [`ServiceConnector`]; the former
/// chooses the target for connecting to, and the latter describes how to
/// establish a connection to that target.
pub struct ServiceInitializer<C, M> {
    service_connector: C,
    connection_manager: M,
}

impl<C, M> ServiceInitializer<C, M>
where
    M: ConnectionManager,
    C: ServiceConnector<
            Service: Send,
            Channel: Send,
            ConnectError: Send + Sync + Debug + LogSafeDisplay + ErrorClassifier,
        > + Send
        + Sync,
{
    pub fn new(service_connector: C, connection_manager: M) -> Self {
        Self {
            service_connector,
            connection_manager,
        }
    }

    pub async fn connect(&self) -> ServiceState<C::Service, C::ConnectError> {
        log::debug!("attempting a connection");
        let connection_attempt_result = self
            .connection_manager
            .connect_or_wait(|connection_params| {
                log::debug!(
                    "trying to connect to {}:{}",
                    connection_params.transport.tcp_host,
                    connection_params.transport.port
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

pub(crate) struct ServiceInner<C: ServiceConnector, M> {
    state: Mutex<ServiceState<C::Service, C::ConnectError>>,
    service_initializer: ServiceInitializer<C, M>,
    connection_timeout: Duration,
}

/// A cheaply-clonable object that wraps a [`ServiceConnector`] and its created
/// service.
///
/// The service can be connected to and disconnected from. The
/// [`Service::service`] method can be used to obtain the
/// [`ServiceConnector::Service`] for the wrapped connector.
#[derive(Clone)]
pub struct Service<C: ServiceConnector, M> {
    data: Arc<ServiceInner<C, M>>,
}

#[derive(Debug, Display)]
pub enum ConnectError<E: LogSafeDisplay> {
    /// Operation timed out
    Timeout { attempts: u16 },
    /// All attempted routes failed to connect
    AllRoutesFailed { attempts: u16 },
    /// Rejected by server: {0}
    RejectedByServer(E),
}

impl<E: LogSafeDisplay> ErrorClassifier for ConnectError<E> {
    fn classify(&self) -> ErrorClass {
        match self {
            ConnectError::Timeout { .. } | ConnectError::AllRoutesFailed { .. } => {
                ErrorClass::Intermittent
            }
            ConnectError::RejectedByServer(_) => ErrorClass::Fatal,
        }
    }
}

#[derive(Debug, Display)]
pub enum StateError {
    /// Service is in the inactive state
    Inactive,
    /// Service is unavailable due to the lost connection
    ServiceUnavailable,
}

impl<C, M> Service<C, M>
where
    C: ServiceConnector,
{
    async fn map_service<T>(&self, mapper: fn(&C::Service) -> T) -> Result<T, StateError> {
        let guard = self.data.state.lock().await;
        match &*guard {
            ServiceState::Active(service, status) if !status.is_cancelled() => Ok(mapper(service)),
            ServiceState::Inactive => Err(StateError::Inactive),
            ServiceState::Cooldown(_)
            | ServiceState::ConnectionTimedOut
            | ServiceState::Error(_)
            | ServiceState::Active(_, _) => Err(StateError::ServiceUnavailable),
        }
    }
}

impl<C, M> Service<C, M>
where
    C: ServiceConnector<Service: RemoteAddressInfo>,
{
    pub async fn connection_info(&self) -> Result<ServiceConnectionInfo, StateError> {
        self.map_service(|s| s.connection_info().clone()).await
    }
}

impl<C, M> Service<C, M>
where
    M: ConnectionManager + 'static,
    C: ServiceConnector<
            Service: Clone + Send + Sync + 'static,
            Channel: Send,
            ConnectError: Send + Sync + Debug + LogSafeDisplay + ErrorClassifier,
        > + Send
        + Sync
        + 'static,
{
    pub fn new(service_connector: C, connection_manager: M, connection_timeout: Duration) -> Self {
        Self {
            data: Arc::new(ServiceInner {
                state: Mutex::new(ServiceState::Inactive),
                service_initializer: ServiceInitializer::new(service_connector, connection_manager),
                connection_timeout,
            }),
        }
    }

    pub async fn connect(&self) -> Result<(), ConnectError<C::ConnectError>> {
        self.do_connect().await
    }

    async fn do_connect(&self) -> Result<(), ConnectError<C::ConnectError>> {
        let mut attempts: u16 = 0;
        let start_of_connection_process = Instant::now();
        let deadline = start_of_connection_process + self.data.connection_timeout;
        let deadline_for_starting = deadline - MINIMUM_CONNECTION_TIME;

        let mut guard = match timeout_at(deadline, self.data.state.lock()).await {
            Ok(guard) => guard,
            Err(_) => {
                log::info!("Timed out waiting for the state lock");
                return Err(ConnectError::Timeout { attempts });
            }
        };
        let lock_taken_instant = Instant::now();

        loop {
            match &*guard {
                ServiceState::Inactive => {
                    // proceeding to connect
                }
                ServiceState::Active(_, service_status) => {
                    if !service_status.is_cancelled() {
                        // if the state is `Active` and service has not been stopped,
                        // clone the service and return it
                        log::debug!("reusing active service instance");
                        return Ok(());
                    }
                }
                ServiceState::Cooldown(next_attempt_time) => {
                    // checking if the `next_attempt_time` is still in the future
                    if next_attempt_time > &deadline_for_starting {
                        log::info!(
                            "All possible routes are in cooldown state until {:?} from now",
                            next_attempt_time.saturating_duration_since(lock_taken_instant)
                        );
                        return Err(ConnectError::AllRoutesFailed { attempts });
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
                }
                ServiceState::Error(e) => {
                    if attempts > 0 {
                        // Only log about errors that happened on *this* connect attempt.
                        log::info!("Connection attempt resulted in an error: {}", e);
                    }

                    match e.classify() {
                        ErrorClass::Intermittent => {
                            // short-circuiting mechanism is responsibility of the `ConnectionManager`,
                            // so here we're just going to keep trying until we get into
                            // one of the non-retryable states, `Cooldown` or time out.
                        }
                        ErrorClass::RetryAt(next_attempt_time) => {
                            *guard = ServiceState::Cooldown(next_attempt_time);
                            continue;
                        }
                        ErrorClass::Fatal => {
                            let state = std::mem::replace(&mut *guard, ServiceState::Inactive);
                            let ServiceState::Error(e) = state else {
                                unreachable!("we checked this above, matching on &*guard");
                            };
                            return Err(ConnectError::RejectedByServer(e));
                        }
                    }
                }
            };

            if Instant::now() >= deadline_for_starting {
                // Don't bother trying to connect if we only have a little bit of time left.
                // This helps debounce repeated connection attempts.
                log::debug!(
                    "skipping connection attempt due to only a little bit of time remaining"
                );
                return Err(ConnectError::Timeout { attempts });
            }

            attempts += 1;
            *guard = timeout_at(deadline, self.data.service_initializer.connect())
                .await
                .unwrap_or(ServiceState::ConnectionTimedOut);
        }
    }

    pub async fn disconnect(&self) {
        let mut guard = self.data.state.lock().await;
        if let ServiceState::Active(_, service_status) = &*guard {
            service_status.cancel(CancellationReason::ExplicitDisconnect);
        }
        *guard = ServiceState::Inactive;
        log::info!("service disconnected");
    }

    pub async fn service(&self) -> Result<C::Service, StateError> {
        self.map_service(|service| service.clone()).await
    }
}

#[cfg(test)]
mod test {
    use std::fmt::Debug;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use futures_util::FutureExt;
    use nonzero_ext::nonzero;
    use tokio::time;
    use tokio::time::Instant;

    use super::*;
    use crate::certs::RootCertificates;
    use crate::connection_manager::SingleRouteThrottlingConnectionManager;
    use crate::host::Host;
    use crate::testutil::{
        ClassifiableTestError, LONG_CONNECTION_TIME, NORMAL_CONNECTION_TIME, TIMEOUT_DURATION,
        TIME_ADVANCE_VALUE,
    };
    use crate::timeouts::CONNECTION_ROUTE_MAX_COOLDOWN;
    use crate::utils::{sleep_and_catch_up, ObservableEvent};
    use crate::{ConnectionParams, HttpRequestDecoratorSeq, RouteType, TransportConnectionParams};

    #[derive(Clone, Debug)]
    struct TestService;

    #[derive(Clone)]
    struct TestServiceConnector {
        attempts: Arc<AtomicI32>,
        time_to_connect: Arc<Mutex<Duration>>,
        connection_error: Arc<Mutex<Option<ClassifiableTestError>>>,
    }

    impl TestServiceConnector {
        fn new() -> Self {
            Self {
                attempts: Arc::new(AtomicI32::new(0)),
                time_to_connect: Arc::new(Mutex::new(NORMAL_CONNECTION_TIME)),
                connection_error: Arc::new(Mutex::new(None)),
            }
        }

        fn attempts_made(&self) -> i32 {
            self.attempts.fetch_or(0, Ordering::Relaxed)
        }

        fn set_time_to_connect(&self, time_to_connect: Duration) {
            let mut guard = self.time_to_connect.lock().unwrap();
            *guard = time_to_connect;
        }

        fn set_connection_error(&self, connection_error: Option<ClassifiableTestError>) {
            *self.connection_error.lock().unwrap() = connection_error;
        }
    }

    #[async_trait]
    impl ServiceConnector for TestServiceConnector {
        type Service = TestService;
        type Channel = ();
        type ConnectError = ClassifiableTestError;

        async fn connect_channel(
            &self,
            _connection_params: &ConnectionParams,
        ) -> Result<Self::Channel, Self::ConnectError> {
            let connection_time = *self.time_to_connect.lock().unwrap();
            let connection_error = self.connection_error.lock().unwrap().clone();
            tokio::time::sleep(connection_time).await;
            self.attempts.fetch_add(1, Ordering::Relaxed);
            if let Some(connection_error) = connection_error {
                Err(connection_error)
            } else {
                Ok(())
            }
        }

        fn start_service(&self, _channel: Self::Channel) -> (Self::Service, CancellationToken) {
            let service_cancellation = CancellationToken::new();
            let service = TestService;
            (service, service_cancellation)
        }
    }

    fn example_connection_params() -> ConnectionParams {
        let host = "chat.signal.org".into();
        ConnectionParams {
            route_type: RouteType::Test,
            transport: TransportConnectionParams {
                sni: Arc::clone(&host),
                tcp_host: Host::Domain(Arc::clone(&host)),
                port: nonzero!(443u16),
                certs: RootCertificates::Native,
            },
            http_host: host,
            http_request_decorator: HttpRequestDecoratorSeq::default(),
            connection_confirmation_header: None,
        }
    }

    #[tokio::test]
    async fn service_not_started_before_first_request() {
        let connector = TestServiceConnector::new();
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(),
            TIMEOUT_DURATION,
            &ObservableEvent::default(),
        );
        let _ = Service::new(connector.clone(), manager, TIMEOUT_DURATION);
        assert_eq!(connector.attempts_made(), 0);
    }

    #[tokio::test]
    async fn service_started_with_request() {
        let (connector, service) = connector_and_service();
        service.connect().await.expect("");
        let _service = service.service().await;
        assert_eq!(connector.attempts_made(), 1);
    }

    #[tokio::test]
    async fn service_is_inactive_before_connected() {
        let (_, service) = connector_and_service();
        assert_matches!(service.service().await, Err(StateError::Inactive));
    }

    #[tokio::test(start_paused = true)]
    async fn service_doesnt_reconnect_if_disconnected() {
        let (_, service) = connector_and_service();
        service.connect().await.expect("connected");

        // making sure service is available
        let _ = service.service().await.expect("available");

        service.disconnect().await;

        // advancing time to make sure that reconnect logic is executed and doesn't reconnect
        time::advance(TIME_ADVANCE_VALUE).await;

        // now when we're trying to get the service, it should be in `Inactive` state
        assert_matches!(service.service().await, Err(StateError::Inactive));
    }

    #[tokio::test]
    async fn immediately_fail_if_in_cooldown() {
        let (connector, service) = connector_and_service();

        connector.set_connection_error(Some(ClassifiableTestError(ErrorClass::Intermittent)));
        let connection_result = service.connect().await;

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
            Err(ConnectError::AllRoutesFailed { attempts: 3 })
        );

        assert_matches!(*service.data.state.lock().await, ServiceState::Cooldown(_));

        let now_or_never_service_option = service.service().now_or_never();
        // the future should be completed immediately
        // but the result of the future should be `Err()` because we're in cooldown
        assert!(now_or_never_service_option
            .expect("completed future")
            .is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multiple_callers_single_attempt() {
        let (connector, service) = connector_and_service();

        let aaa1 = service.clone();
        let handle1 = tokio::spawn(async move { aaa1.connect().await });

        let aaa2 = service.clone();
        let handle2 = tokio::spawn(async move { aaa2.connect().await });

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
        let service_timeout = TIMEOUT_DURATION * 2;

        let connector = TestServiceConnector::new();
        connector.set_time_to_connect(connection_time);
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(),
            connection_timeout,
            &ObservableEvent::default(),
        );
        let service = Service::new(connector.clone(), manager, service_timeout);
        let res = service.connect().await;

        // now the time should've auto-advanced from `start` by the `connection_timeout` value
        assert!(res.is_err());
        assert_eq!(Instant::now(), start + service_timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn service_returns_if_connection_time_exceeds_its_own_timeout() {
        let start = Instant::now();
        let connection_time = LONG_CONNECTION_TIME;
        let connection_timeout = TIMEOUT_DURATION * 2;
        let service_timeout = TIMEOUT_DURATION;

        let connector = TestServiceConnector::new();
        connector.set_time_to_connect(connection_time);

        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(),
            connection_timeout,
            &ObservableEvent::default(),
        );
        let service = Service::new(connector.clone(), manager, service_timeout);
        let res = service.connect().await;

        // now the time should've auto-advanced from `start` by the `connection_timeout` value
        assert_matches!(res, Err(ConnectError::Timeout { attempts: 1 }));
        assert_eq!(Instant::now(), start + service_timeout);
    }

    #[tokio::test(start_paused = true)]
    async fn service_able_to_connect_after_failed_attempt() {
        let (connector, service) = connector_and_service();

        time::advance(TIME_ADVANCE_VALUE).await;
        connector.set_connection_error(Some(ClassifiableTestError(ErrorClass::Intermittent)));
        let connection_result = service.connect().await;

        // number of attempts is the same as in the `immediately_fail_if_in_cooldown()` test
        assert_matches!(
            connection_result,
            Err(ConnectError::AllRoutesFailed { attempts: 3 })
        );

        // At this point, `service` tried multiple times to connect and hit the
        // cooldown. Let's advance time to make sure next attempt will be made.
        time::advance(CONNECTION_ROUTE_MAX_COOLDOWN).await;

        connector.set_connection_error(None);
        let connection_result = service.connect().await;
        assert_matches!(connection_result, Ok(_));
    }

    #[tokio::test(start_paused = true)]
    async fn service_able_to_connect_after_timed_out_attempt() {
        let (connector, service) = connector_and_service();
        time::advance(TIME_ADVANCE_VALUE).await;
        connector.set_time_to_connect(LONG_CONNECTION_TIME);
        let connection_result = service.connect().await;
        assert_matches!(
            connection_result,
            Err(ConnectError::Timeout { attempts: 1 })
        );

        // At this point, `service` tried multiple times to connect and hit the
        // cooldown. Let's advance time to make sure next attempt will be made.
        time::advance(CONNECTION_ROUTE_MAX_COOLDOWN).await;

        connector.set_time_to_connect(NORMAL_CONNECTION_TIME);
        let connection_result = service.connect().await;
        assert_matches!(connection_result, Ok(_));
    }

    #[tokio::test(start_paused = true)]
    async fn service_times_out_early_on_guard_contention() {
        let (connector, service) = connector_and_service();
        let guard = service.data.state.lock().await;

        let service_for_task = service.clone();
        let connection_task = tokio::spawn(async move { service_for_task.connect().await });

        sleep_and_catch_up(TIMEOUT_DURATION - MINIMUM_CONNECTION_TIME).await;
        drop(guard);

        let connection_result = connection_task.await.expect("joined successfully");
        assert_matches!(
            connection_result,
            Err(ConnectError::Timeout { attempts: 0 })
        );
        assert_eq!(connector.attempts_made(), 0);
    }

    fn connector_and_service() -> (
        TestServiceConnector,
        Service<TestServiceConnector, SingleRouteThrottlingConnectionManager>,
    ) {
        let connector = TestServiceConnector::new();
        let manager = SingleRouteThrottlingConnectionManager::new(
            example_connection_params(),
            TIMEOUT_DURATION,
            &ObservableEvent::default(),
        );
        let service = Service::new(connector.clone(), manager, TIMEOUT_DURATION);
        (connector, service)
    }
}
