//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use futures_util::{Sink, Stream};
use pin_project::pin_project;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::route::connect::Connector;
use crate::{Connection, TransportInfo};

/// [`Connector`] wrapper that limits the number of concurrent connection
/// attempts.
///
/// Wraps a `Connector` impl to prevent delay starting a connection attempt
/// until a permit is acquired from the [`Semaphore`] owned by the connector. A
/// successful connection is paired with the semaphore permit. This can be used
/// to limit the number of successfully-created connections that can exist at a
/// time. See the [`ThrottledConnection`] docs for more details.
pub struct ThrottlingConnector<C> {
    inner: C,
    permits: Arc<Semaphore>,
}

impl<C> ThrottlingConnector<C> {
    /// Wrap an inner [`Connector`] with the given limit on the number of
    /// connection attempts that can be in progress at a time.
    pub fn new(connector: C, permits: usize) -> Self {
        Self {
            inner: connector,
            permits: Semaphore::new(permits).into(),
        }
    }
}

/// Pairs a connection `S` with a [`OwnedSemaphorePermit`].
///
/// The semaphore permit comes from the [`ThrottlingConnector`] that produced
/// this connection, and can only be released by dropping this connection.
/// Dropping a `ThrottlingConnector` unblocks one in-progress call to
/// [`Connector::connect_over`].
#[derive(Debug)]
#[pin_project]
pub struct ThrottledConnection<S>(#[pin] S, OwnedSemaphorePermit);

impl<C, R, Inner> Connector<R, Inner> for ThrottlingConnector<C>
where
    R: Send,
    Inner: Send,
    C: Connector<R, Inner> + Sync,
{
    type Connection = ThrottledConnection<C::Connection>;

    type Error = C::Error;

    fn connect_over(
        &self,
        over: Inner,
        route: R,
        log_tag: Arc<str>,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let Self { inner, permits } = self;
        async move {
            let permit = Arc::clone(permits)
                .acquire_owned()
                .await
                .expect("semaphore not closed");
            let connection = inner.connect_over(over, route, log_tag).await?;
            Ok(ThrottledConnection(connection, permit))
        }
    }
}

impl<S> AsRef<S> for ThrottledConnection<S> {
    fn as_ref(&self) -> &S {
        &self.0
    }
}

impl<S> AsMut<S> for ThrottledConnection<S> {
    fn as_mut(&mut self) -> &mut S {
        &mut self.0
    }
}

impl<S> ThrottledConnection<S> {
    pub fn as_pin_ref(self: Pin<&Self>) -> Pin<&S> {
        self.project_ref().0
    }
}

impl<S> ThrottledConnection<S> {
    pub fn as_pin_mut(self: Pin<&mut Self>) -> Pin<&mut S> {
        self.project().0
    }
}

impl<S: Stream> Stream for ThrottledConnection<S> {
    type Item = S::Item;

    fn poll_next(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.as_pin_mut().poll_next(cx)
    }
}

impl<S: Sink<T>, T> Sink<T> for ThrottledConnection<S> {
    type Error = S::Error;

    fn poll_ready(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.as_pin_mut().poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: T) -> Result<(), Self::Error> {
        self.as_pin_mut().start_send(item)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.as_pin_mut().poll_flush(cx)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.as_pin_mut().poll_close(cx)
    }
}

impl<C: Connection> Connection for ThrottledConnection<C> {
    fn transport_info(&self) -> TransportInfo {
        self.0.transport_info()
    }
}

impl<S: AsyncRead> AsyncRead for ThrottledConnection<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.as_pin_mut().poll_read(cx, buf)
    }
}

impl<S: AsyncWrite> AsyncWrite for ThrottledConnection<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        self.as_pin_mut().poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        self.as_pin_mut().poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        self.as_pin_mut().poll_shutdown(cx)
    }
}
