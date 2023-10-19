//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::infra::connection_manager::{ConnectionAttemptOutcome, ConnectionManager};
use crate::infra::errors::LogSafeDisplay;
use crate::infra::ConnectionParams;
use async_trait::async_trait;
use std::fmt::Debug;
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub(crate) const ERRORS_CHANNEL_BUFFER_SIZE: usize = 1;

/// For a service that needs to go through some initialization procedure
/// before it's ready for use, this enum describes its possible states.
/// It's best understood in the context of an `async` function
/// that is supposed to return an instance of the service:
/// - `Active` - then the value held by it
///   is ready to use and could be immediately returned
/// - `Inactive` - the function should kick off the initialization and
///   wait until it's complete.
/// - `Pending` - another call had already triggered initialization, but it's not completed yet.
///   The function should wait for until this state changes.
/// - `Cooldown` - the service is inactive and no initialization attempts are to be made
///   until the `Instant` held by this object. The function should immediately return
///   with an unsuccessful result.
#[derive(Clone, Debug)]
pub enum ServiceState<T> {
    /// Contains an instance of the service which is initialized and ready to use.
    Active(T),
    /// The service is inactive but is ready for an initialization procedure to be kicked off.
    Inactive,
    /// Initialization of the service has been kicked off,
    /// it would make sense for the client to wait until it's completed
    Pending,
    /// The service is inactive and no initialization attempts are to be made
    /// until the `Instant` held by this object.
    Cooldown(Instant),
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

    fn start_service(
        &self,
        channel: Self::Channel,
    ) -> (Self::Service, ServiceControls<Self::Error>);
}

pub struct ServiceControls<E> {
    pub errors_rx: mpsc::Receiver<E>,
    pub service_cancellation: CancellationToken,
}

impl<E> ServiceControls<E> {
    pub fn new(errors_rx: mpsc::Receiver<E>, service_cancellation: CancellationToken) -> Self {
        Self {
            errors_rx,
            service_cancellation,
        }
    }
}

#[derive(Clone)]
pub struct ServiceWithReconnect<T> {
    service_watch: watch::Receiver<ServiceState<T>>,
    connection_request_tx: mpsc::Sender<()>,
}

impl<T> ServiceWithReconnect<T>
where
    T: Clone + Send + Sync + 'static,
{
    pub fn start<M, C>(service_connector: C, connection_manager: M) -> ServiceWithReconnect<T>
    where
        M: ConnectionManager + 'static,
        C: ServiceConnector<Service = T> + Send + Sync + 'static,
        C::Channel: Send + Sync,
        C::Error: Send + Debug + LogSafeDisplay,
    {
        let (service_watch_sender, service_watch) = watch::channel(ServiceState::Pending);
        let (connection_request_tx, connection_request_rx) = mpsc::channel::<()>(1);
        let mut reconnect_helper = ReconnectHelper {
            service_watch_sender,
            connection_manager,
            service_connector,
            connection_request_rx,
        };
        tokio::spawn(async move {
            reconnect_helper.event_loop().await;
        });
        ServiceWithReconnect {
            service_watch,
            connection_request_tx,
        }
    }

    pub(crate) async fn service_clone(&mut self) -> Option<T> {
        // Sending this message ensures that we're kicking `ServiceWithReconnect` form `Inactive`
        // state. The only situation where we may end up waiting is when we're already in `Pending`
        // state in which case we're about to wait anyway.
        let _ignore_failed_send = self.connection_request_tx.send(()).await;
        match self.service_watch.has_changed() {
            Ok(mut wait_for_new_val) => loop {
                // When we first enter this loop, we should only wait
                // for the `service_watch` value to change if it has changed
                // since we last consumed it. On every new iteration we need to wait for
                // the change in the value.
                let val_updated_event = match wait_for_new_val {
                    true => self.service_watch.changed().await,
                    false => Ok(()),
                };
                match val_updated_event {
                    Ok(_) => match &*(self.service_watch.borrow_and_update()) {
                        ServiceState::Active(s) => {
                            log::debug!("service is active");
                            return Some(s.clone());
                        }
                        ServiceState::Pending => {
                            log::debug!("service is pending");
                            wait_for_new_val = true
                        }
                        ServiceState::Cooldown(_) => {
                            log::debug!("service is cooling down");
                            return None;
                        }
                        ServiceState::Inactive => {
                            // there is a chance of ending up in `Inactive` state,
                            // we should treat the same way as if we're in `Cooldown`
                            log::debug!("service is in `inactive` state");
                            return None;
                        }
                    },
                    Err(_) => return None,
                }
            },
            Err(_) => None,
        }
    }
}

struct ReconnectHelper<T, M, C> {
    service_watch_sender: watch::Sender<ServiceState<T>>,
    connection_manager: M,
    service_connector: C,
    connection_request_rx: mpsc::Receiver<()>,
}

impl<T, M, C> ReconnectHelper<T, M, C>
where
    T: Clone,
    M: ConnectionManager + 'static,
    C: ServiceConnector<Service = T> + Send + Sync + 'static,
    C::Channel: Send + Sync,
    C::Error: Send + Debug + LogSafeDisplay,
{
    async fn event_loop(&mut self) {
        loop {
            let controls = self.inactive_state_events_handler().await;
            if controls.is_none() {
                return;
            }
            self.active_state_events_handler(controls.unwrap()).await;
        }
    }

    /// This method represents a state machine of the `ServiceWithReconnect`
    /// when it's in a connected state. This method returns when connection channel closes
    async fn active_state_events_handler(&mut self, mut controls: ServiceControls<C::Error>) {
        loop {
            enum Event<E> {
                Error(Option<E>),
                ChannelClosed,
                ConnectionRequest(bool),
            }
            match tokio::select! {
                r = self.connection_request_rx.recv() => Event::ConnectionRequest(r.is_some()),
                _ = controls.service_cancellation.cancelled() => Event::ChannelClosed,
                e = controls.errors_rx.recv() => Event::Error(e),
            } {
                Event::ConnectionRequest(true) => {
                    // new connection requests are ignored since we're already connected,
                    // however, we still need to process events on this channel even though
                    // we're just discarding them
                }
                Event::ConnectionRequest(false) => {
                    // if connection request subscriber received `None`, it means that the
                    // publisher was dropped and we can now exit
                    return;
                }
                Event::ChannelClosed => {
                    log::debug!("channel closed");
                    // shifting to `Inactive` state
                    let _ignore_failed_send =
                        self.service_watch_sender.send(ServiceState::Inactive);
                    break;
                }
                Event::Error(Some(error)) => {
                    // got an error, should write something to log, also, maybe report to
                    // a circuit breaker
                    log::debug!("service reported an error: {:?}", error);
                    controls.service_cancellation.cancel();
                }
                Event::Error(None) => {
                    // all errors publishers are dropped, should not be getting here before
                    // the cancellation
                    controls.service_cancellation.cancel();
                }
            }
        }
    }

    /// This method represents a state machine of the `ServiceWithReconnect`
    /// when it's in a not connected state. This method will only return
    /// when a connection is established.
    async fn inactive_state_events_handler(&mut self) -> Option<ServiceControls<C::Error>> {
        let mut not_earlier_than = Instant::now();
        loop {
            // Waiting for someone to request a connection.
            // This only serves as a signal for the service to move out of the `Inactive` state.
            // If request arrives at the time when the service is in a cooldown state,
            // we're not going to try and reconnect after the cooldown is over because by that time
            // this connection may not be needed and we're trying to avoid creating connections
            // proactively.
            self.connection_request_rx.recv().await?;

            // checking if we're in the cooldown state
            if Instant::now() < not_earlier_than {
                continue;
            }
            // attempting to establish a connection until we're connected or instructed to cooldown
            loop {
                // shifting to `Pending` state
                let _ignore_failed_send = self.service_watch_sender.send(ServiceState::Pending);
                let connection_attempt_result = self
                    .connection_manager
                    .connect_or_wait(&|connection_params| {
                        self.service_connector.connect_channel(connection_params)
                    })
                    .await;

                match connection_attempt_result {
                    ConnectionAttemptOutcome::Attempted(Ok(channel)) => {
                        log::debug!("connection attempted and succeeded");
                        let (service, extra) = self.service_connector.start_service(channel);
                        // shifting to `Active` state and returning
                        let _ignore_failed_send = self
                            .service_watch_sender
                            .send(ServiceState::Active(service));
                        return Some(extra);
                    }
                    ConnectionAttemptOutcome::Attempted(Err(e)) => {
                        log::debug!("connection attempted and failed due to an error: {:?}", e);
                        continue;
                    }
                    ConnectionAttemptOutcome::WaitUntil(i) if i <= Instant::now() => {
                        log::debug!("cooldown time is in the past, retrying immediately");
                        continue;
                    }
                    ConnectionAttemptOutcome::WaitUntil(i) => {
                        log::debug!(
                            "connection will not be attempted for another {} seconds",
                            i.duration_since(Instant::now()).as_secs()
                        );
                        // shifting to `Cooldown` state and updating `not_earlier_than` variable
                        let _ignore_failed_send =
                            self.service_watch_sender.send(ServiceState::Cooldown(i));
                        not_earlier_than = i;
                        break;
                    }
                }
            }
        }
    }
}
