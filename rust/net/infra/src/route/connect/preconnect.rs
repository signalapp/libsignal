//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::sync::Arc;
use std::time::Duration;

use tokio::time::Instant;

use super::{Connector, ConnectorFactory};

/// A [`ConnectorFactory`] wrapper that can be directed to save and restore a single existing
/// connection.
///
/// If used normally, `PreconnectingFactory` just passes through to its inner factory connector.
/// However, a previous connection can also be saved using [`Self::save_preconnected`]; if
/// subsequently directed to connect over a [`UsePreconnect`] route, it will (conditionally) check
/// for such a connection and return that rather than forming a new one, at least if the route
/// matches up.
///
/// Only one connection will be saved at a time; all connectors created by the same factory will
/// share the same saved connection state. A successful connect over a [`UsePreconnect`] route will
/// clear the saved connection whether or not it was used, so as not to hold onto resources
/// unnecessarily.
pub struct PreconnectingFactory<R, F: ConnectorFactory<R>> {
    inner_factory: F,
    shared: Arc<SharedState<R, F::Connection>>,
}

/// For "normal" routes, the factory acts as a passthrough.
impl<R, F: ConnectorFactory<R>> ConnectorFactory<R> for PreconnectingFactory<R, F> {
    type Connector = F::Connector;
    type Connection = F::Connection;

    fn make(&self) -> Self::Connector {
        self.inner_factory.make()
    }
}

impl<R, F: ConnectorFactory<R>> ConnectorFactory<UsePreconnect<R>> for PreconnectingFactory<R, F>
where
    PreconnectingConnector<R, F::Connector>: Connector<UsePreconnect<R>, ()>,
{
    type Connector = PreconnectingConnector<R, F::Connector>;
    type Connection = <Self::Connector as Connector<UsePreconnect<R>, ()>>::Connection;

    fn make(&self) -> Self::Connector {
        PreconnectingConnector {
            connector: self.inner_factory.make(),
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<R, F: ConnectorFactory<R>> PreconnectingFactory<R, F> {
    /// Wraps `inner_factory` and establishes `timeout` as the length of time before a saved
    /// connection is considered to have expired.
    pub fn new(inner_factory: F, timeout: Duration) -> Self {
        Self {
            inner_factory,
            shared: SharedState {
                timeout,
                saved: Default::default(),
            }
            .into(),
        }
    }

    pub fn save_preconnected(&self, route: R, connection: F::Connection, established: Instant) {
        let mut saved_guard = self.shared.saved.lock().expect("not poisoned");
        if saved_guard
            .as_ref()
            .is_some_and(|existing| existing.established > established)
        {
            return;
        }
        *saved_guard = Some(SavedConnection {
            connection,
            route,
            established,
        });
    }
}

/// The [`Connector`] produced by [`PreconnectingFactory`].
pub struct PreconnectingConnector<R, C: Connector<R, ()>> {
    connector: C,
    shared: Arc<SharedState<R, C::Connection>>,
}

/// Persistent state for a [`PreconnectingFactory`] shared with all created
/// [`PreconnectingConnector`]s.
///
/// See also [`SavedConnection`].
struct SharedState<R, C> {
    timeout: Duration,
    saved: std::sync::Mutex<Option<SavedConnection<R, C>>>,
}

/// A saved connection for [`PreconnectingConnector`].
///
/// A separate type from [`SharedState`] because it's inside a mutex.
struct SavedConnection<R, T> {
    route: R,
    connection: T,
    established: Instant,
}

impl<R, C: Connector<R, ()> + Sync> Connector<UsePreconnect<R>, ()> for PreconnectingConnector<R, C>
where
    R: Eq + Send + Clone,
    C::Connection: Send,
{
    type Connection = C::Connection;
    type Error = C::Error;

    async fn connect_over(
        &self,
        _over: (),
        route: UsePreconnect<R>,
        log_tag: &str,
    ) -> Result<Self::Connection, Self::Error> {
        if route.should {
            let mut saved_guard = self.shared.saved.lock().expect("not poisoned");
            if let Some(saved) = saved_guard.take() {
                if saved.established.elapsed() >= self.shared.timeout {
                    // The connection expired, whether it was for this route or not.
                    log::debug!("[{log_tag}] expiring old preconnection");
                } else if saved.route == route.inner {
                    log::info!("[{log_tag}] using preconnection");
                    return Ok(saved.connection);
                } else {
                    // We have a saved connection, but it's for a different route. Assuming we try
                    // routes in preference order, we should go ahead trying to connect this one.
                    // But put the saved connection back in case we get to it later.
                    log::debug!("[{log_tag}] ignoring preconnection");
                    *saved_guard = Some(saved);
                }
            }
        }

        let connection = self
            .connector
            .connect_over((), route.inner, log_tag)
            .await?;

        if route.should {
            // Assume we don't need the saved connection anymore.
            // Note that there's a potential race here: if a save_preconnect() call races a
            // connect() call, we could end up clearing a *different* connection from the one we set
            // above. But if we really cared about that, we'd be willing to save more than one
            // connection at a time. For now, just don't worry about it; preconnecting is an
            // optimization.
            *self.shared.saved.lock().expect("not poisoned") = None;
        }

        Ok(connection)
    }
}

/// A marker to wrap routes in for use with [`PreconnectingConnector`].
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct UsePreconnect<R> {
    pub should: bool,
    pub inner: R,
}

#[cfg(test)]
mod test {
    use std::sync::atomic::{self, AtomicU8};

    use assert_matches::assert_matches;

    use super::*;
    use crate::route::ConnectorExt;
    use crate::route::testutils::ConnectFn;

    const TIMEOUT: Duration = Duration::from_secs(1);

    fn test_factory(
        number_of_times_called: &AtomicU8,
    ) -> PreconnectingFactory<
        i32,
        impl ConnectorFactory<
            i32,
            Connector: Connector<i32, (), Error = &'static str> + Sync,
            Connection = u32,
        > + '_,
    > {
        let inner_connector = ConnectFn(|_over: (), route: i32| {
            number_of_times_called.fetch_add(1, atomic::Ordering::SeqCst);
            std::future::ready(u32::try_from(route).map_err(|_| "negative"))
        });
        PreconnectingFactory::new(inner_connector, TIMEOUT)
    }

    /// A convenience for writing tests that *want* to use a preconnect.
    fn pre<T>(route: T) -> UsePreconnect<T> {
        UsePreconnect {
            should: true,
            inner: route,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn passthrough() {
        let number_of_times_called = AtomicU8::new(0);
        let factory = test_factory(&number_of_times_called);

        // Passthrough behavior when there's no saved connection.
        let connector = ConnectorFactory::<UsePreconnect<_>>::make(&factory);
        assert_matches!(connector.connect(pre(1), "1").await, Ok(1));
        assert_matches!(connector.connect(pre(-1), "-1").await, Err("negative"));
        assert_eq!(number_of_times_called.load(atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn successes_are_used_unless_timed_out() {
        let number_of_times_called = AtomicU8::new(0);
        let factory = test_factory(&number_of_times_called);

        factory.save_preconnected(1, 10, Instant::now());
        let connector = ConnectorFactory::<UsePreconnect<_>>::make(&factory);
        assert_matches!(connector.connect(pre(1), "1").await, Ok(10));
        assert_eq!(number_of_times_called.load(atomic::Ordering::SeqCst), 0);

        assert_matches!(connector.connect(pre(1), "1 again").await, Ok(1));
        assert_eq!(
            number_of_times_called.load(atomic::Ordering::SeqCst),
            1,
            "can't use a saved route more than once"
        );

        factory.save_preconnected(2, 20, Instant::now());
        tokio::time::sleep(TIMEOUT).await;
        assert_matches!(connector.connect(pre(2), "2").await, Ok(2));
        assert_eq!(
            number_of_times_called.load(atomic::Ordering::SeqCst),
            2,
            "now the saved connection has timed out"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn respects_should_field() {
        let number_of_times_called = AtomicU8::new(0);
        let factory = test_factory(&number_of_times_called);

        factory.save_preconnected(1, 10, Instant::now());
        let connector = ConnectorFactory::<UsePreconnect<_>>::make(&factory);
        assert_matches!(
            connector
                .connect(
                    UsePreconnect {
                        should: false,
                        inner: 1
                    },
                    "1"
                )
                .await,
            Ok(1)
        );
        assert_eq!(number_of_times_called.load(atomic::Ordering::SeqCst), 1);

        // The preconnect should still be there.
        assert_matches!(connector.connect(pre(1), "1").await, Ok(10));
        assert_eq!(number_of_times_called.load(atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn connect_without_wrapper_ignores_saved() {
        let number_of_times_called = AtomicU8::new(0);
        let factory = test_factory(&number_of_times_called);

        factory.save_preconnected(1, 10, Instant::now());
        let connector = ConnectorFactory::<i32>::make(&factory);
        assert_matches!(connector.connect(1, "1").await, Ok(1u32));
        assert_eq!(number_of_times_called.load(atomic::Ordering::SeqCst), 1);

        // The preconnect should still be there.
        let connector = ConnectorFactory::<UsePreconnect<_>>::make(&factory);
        assert_matches!(connector.connect(pre(1), "1").await, Ok(10));
        assert_eq!(number_of_times_called.load(atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn only_one_success_is_saved() {
        let number_of_times_called = AtomicU8::new(0);
        let factory = test_factory(&number_of_times_called);

        factory.save_preconnected(1, 10, Instant::now());
        factory.save_preconnected(2, 20, Instant::now());
        let connector = ConnectorFactory::<UsePreconnect<_>>::make(&factory);
        assert_matches!(connector.connect(pre(1), "1").await, Ok(1));
        assert_eq!(number_of_times_called.load(atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn success_clears_saved_connection() {
        let number_of_times_called = AtomicU8::new(0);
        let factory = test_factory(&number_of_times_called);

        factory.save_preconnected(1, 10, Instant::now());
        let connector = ConnectorFactory::<UsePreconnect<_>>::make(&factory);
        assert_matches!(connector.connect(pre(2), "2").await, Ok(2));
        assert_matches!(connector.connect(pre(1), "1").await, Ok(1));
        assert_eq!(number_of_times_called.load(atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn failure_preserves_saved_connection() {
        let number_of_times_called = AtomicU8::new(0);
        let factory = test_factory(&number_of_times_called);

        factory.save_preconnected(1, 10, Instant::now());
        let connector = ConnectorFactory::<UsePreconnect<_>>::make(&factory);
        assert_matches!(connector.connect(pre(-2), "-2").await, Err("negative"));
        assert_eq!(number_of_times_called.load(atomic::Ordering::SeqCst), 1);
        assert_matches!(connector.connect(pre(1), "1").await, Ok(10));
        assert_eq!(number_of_times_called.load(atomic::Ordering::SeqCst), 1);
    }
}
