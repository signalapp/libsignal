//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use futures_util::TryFutureExt as _;

use super::Connector;
use crate::route::ResolvedRoute;
use crate::utils::NetworkChangeEvent;

/// A [`Connector`] that listens for network changes and aborts sooner if one happens *and* a
/// preferred route change is subsequently detected.
pub struct InterfaceMonitor<Inner, F = DefaultGetCurrentInterface> {
    inner: Inner,
    get_current_interface: F,
    network_change_event: NetworkChangeEvent,
    network_change_poll_interval: Duration,
    post_change_grace_period: Duration,
}

/// Similar to [`TimeoutOr`](crate::timeouts::TimeoutOr), but specific to this connector, so code
/// handling it can't accidentally affect other timeouts.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, derive_more::From)]
pub enum InterfaceChangedOr<E> {
    InterfaceChanged,
    Other(#[from] E),
}

impl<E> InterfaceChangedOr<E> {
    pub fn into_inner_or_else(self, replacement: impl FnOnce() -> E) -> E {
        match self {
            InterfaceChangedOr::InterfaceChanged => replacement(),
            InterfaceChangedOr::Other(e) => e,
        }
    }
}

/// An implementation detail of InterfaceMonitor.
///
/// Essentially an [`AsyncFn`] with a few extra constraints; once our MSRV is 1.85, we could
/// consider removing this trait.
pub trait GetCurrentInterface {
    // This is overly general, but there's no reason not to allow it.
    type Representation: Eq + Send + Sync;

    /// Produce a `Representation` of the network interface that would be used to connect to
    /// `target`.
    fn get_interface_for(
        &self,
        target: IpAddr,
    ) -> impl Future<Output = Self::Representation> + Send;
}

impl<Inner> InterfaceMonitor<Inner> {
    pub fn new(
        inner: Inner,
        network_change_event: NetworkChangeEvent,
        network_change_poll_interval: Duration,
        post_change_grace_period: Duration,
    ) -> Self {
        Self {
            inner,
            get_current_interface: Default::default(),
            network_change_event,
            network_change_poll_interval,
            post_change_grace_period,
        }
    }
}

impl<R, Over, Inner, F> Connector<R, Over> for InterfaceMonitor<Inner, F>
where
    R: Send + ResolvedRoute,
    Over: Send,
    Inner: Connector<R, Over> + Sync,
    F: GetCurrentInterface + Sync,
{
    type Connection = Inner::Connection;
    type Error = InterfaceChangedOr<Inner::Error>;

    async fn connect_over(
        &self,
        over: Over,
        route: R,
        log_tag: &str,
    ) -> Result<Self::Connection, Self::Error> {
        // We need our own Receiver so that multiple connections can be going at once.
        let mut network_change_event = self.network_change_event.clone();
        network_change_event.mark_unchanged();

        let target_ip = *route.immediate_target();
        let initial_interface = self
            .get_current_interface
            .get_interface_for(target_ip)
            .await;

        #[derive(Debug)]
        enum ReasonToCheck {
            NetworkChangeEvent,
            Poll,
        }

        let network_change_timeout = async move {
            loop {
                let time_for_next_poll = tokio::time::sleep(self.network_change_poll_interval);
                let reason = tokio::select! {
                    _ = network_change_event.changed() => ReasonToCheck::NetworkChangeEvent,
                    _ = time_for_next_poll => ReasonToCheck::Poll,
                };

                if initial_interface
                    != self
                        .get_current_interface
                        .get_interface_for(target_ip)
                        .await
                {
                    tokio::time::sleep(self.post_change_grace_period).await;
                    return reason;
                }
            }
        };

        let connect = self.inner.connect_over(over, route, log_tag);
        tokio::select! {
            result = connect => result.map_err(InterfaceChangedOr::Other),
            change_reason = network_change_timeout => {
                log::info!("[{log_tag}] aborting connection attempt early after network change detected by {change_reason:?}");
                Err(InterfaceChangedOr::InterfaceChanged)
            }
        }
    }
}

/// Fetches the local IP address that represents the current preferred network route.
///
/// This is an approximation of our real question, which is "what is the current preferred network
/// route?", that can be compared at multiple points in time during `connect`. Ideally we would get
/// the "baseline" state from the connection that's actually in progress, but if it hasn't even
/// completed a TCP handshake yet there's no way to ask that question using tokio's TcpStream API.
/// So we just make a UDP socket instead and then immediately throw it away.
#[derive(Default)]
pub struct DefaultGetCurrentInterface;

impl GetCurrentInterface for DefaultGetCurrentInterface {
    type Representation = IpAddr;

    async fn get_interface_for(&self, target: IpAddr) -> Self::Representation {
        let unspecified: IpAddr = if target.is_ipv4() {
            std::net::Ipv4Addr::UNSPECIFIED.into()
        } else {
            std::net::Ipv6Addr::UNSPECIFIED.into()
        };

        tokio::net::UdpSocket::bind((unspecified, 0))
            .and_then(|socket| async move {
                // We won't send any packets (UDP connect is a local-only action), but just in case the
                // local system is configured to see what the connection is for we pick a plausible port
                // number: 443, as if we were QUIC.
                socket.connect((target, 443)).await?;
                let ip = socket.local_addr()?.ip();
                log::trace!("local IP: {ip}");
                Ok(ip)
            })
            .await
            .unwrap_or(unspecified)
    }
}

/// Convenient for tests.
#[cfg(any(test, feature = "test-util"))]
impl<T, F: Fn(IpAddr) -> T> GetCurrentInterface for F
where
    T: Future<Output: Eq + Send + Sync> + Send,
{
    type Representation = T::Output;

    fn get_interface_for(
        &self,
        target: IpAddr,
    ) -> impl Future<Output = Self::Representation> + Send {
        self(target)
    }
}

#[cfg(test)]
mod test {
    use std::convert::Infallible;

    use assert_matches::assert_matches;
    use const_str::ip_addr;
    use nonzero_ext::nonzero;
    use test_case::test_matrix;
    use tokio::time::Instant;

    use super::*;
    use crate::OverrideNagleAlgorithm;
    use crate::route::testutils::{ConnectFn, FakeConnectError, NeverConnect};
    use crate::route::{ConnectorExt as _, TcpRoute};

    const ROUTE_CHANGE_INTERVAL: Duration = Duration::from_secs(10);
    const POST_CHANGE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
    /// A smaller divisor of [`ROUTE_CHANGE_INTERVAL`].
    const NETWORK_CHANGE_INTERVAL: Duration = ROUTE_CHANGE_INTERVAL.checked_div(5).unwrap();

    /// Connects over `inner` with either a network change or a poll-timeout every
    /// [`NETWORK_CHANGE_INTERVAL`] and an actual route change happening at
    /// [`ROUTE_CHANGE_INTERVAL`], giving the connection [`POST_CHANGE_CONNECT_TIMEOUT`] to finish.
    async fn try_connection<C>(
        change_events: bool,
        inner: C,
    ) -> Result<C::Connection, InterfaceChangedOr<C::Error>>
    where
        C: Connector<TcpRoute<IpAddr>, ()> + Sync,
    {
        let start = Instant::now();
        let (tx, rx) = tokio::sync::watch::channel(());

        let (poll_interval, network_change_interval) = if change_events {
            (Duration::MAX, NETWORK_CHANGE_INTERVAL)
        } else {
            (NETWORK_CHANGE_INTERVAL, Duration::MAX)
        };

        let connector = InterfaceMonitor {
            inner,
            get_current_interface: |_target| async move {
                #[expect(clippy::cast_possible_truncation)]
                {
                    start.elapsed().div_duration_f32(ROUTE_CHANGE_INTERVAL) as u8
                }
            },
            network_change_event: rx,
            network_change_poll_interval: poll_interval,
            post_change_grace_period: POST_CHANGE_CONNECT_TIMEOUT,
        };

        let background_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval_at(start, network_change_interval);
            // Skip the first tick, the one that happens at 'start'.
            interval.tick().await;
            loop {
                interval.tick().await;
                tx.send_replace(());
            }
        });

        let route = TcpRoute {
            address: ip_addr!("192.0.2.1"),
            port: nonzero!(443u16),
            override_nagle_algorithm: OverrideNagleAlgorithm::UseSystemDefault,
        };

        let result = connector.connect(route, "test").await;

        assert!(!background_task.is_finished(), "only exits on panic");
        background_task.abort();

        result
    }

    #[test_matrix([false, true])]
    #[tokio::test(start_paused = true)]
    async fn network_change_timeout(change_events: bool) {
        let start = Instant::now();
        let result: Result<Infallible, InterfaceChangedOr<FakeConnectError>> =
            try_connection(change_events, NeverConnect).await;

        assert_matches!(result, Err(InterfaceChangedOr::InterfaceChanged));
        assert_eq!(
            start.elapsed(),
            ROUTE_CHANGE_INTERVAL + POST_CHANGE_CONNECT_TIMEOUT,
        );
    }

    #[test_matrix([false, true], [Ok(()), Err(FakeConnectError)], [
        NETWORK_CHANGE_INTERVAL / 2,
        ROUTE_CHANGE_INTERVAL / 2,
        ROUTE_CHANGE_INTERVAL + POST_CHANGE_CONNECT_TIMEOUT / 2
    ])]
    #[tokio::test(start_paused = true)]
    async fn connection_can_still_finish_normally(
        change_events: bool,
        result: Result<(), FakeConnectError>,
        delay: Duration,
    ) {
        let start = Instant::now();
        let actual_result: Result<(), InterfaceChangedOr<FakeConnectError>> = try_connection(
            change_events,
            ConnectFn(|_over, _route| {
                let result = result.clone();
                async move {
                    tokio::time::sleep(delay).await;
                    result
                }
            }),
        )
        .await;

        assert_eq!(result.map_err(InterfaceChangedOr::Other), actual_result);
        assert_eq!(start.elapsed(), delay);
    }
}
