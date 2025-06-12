//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::sync::Arc;

use derive_where::derive_where;

use crate::route::Connector;

/// A [`Connector`] that establishes a connection over the transport provided by
/// an inner connector.
///
/// This implements `Connector` for several different types of routes.
/// Each implementation splits off configuration for a single protocol level,
/// then uses the outer Connector to establish a connection over the transport
/// provided by the inner Connector.
#[derive_where(Debug; Outer: Debug, Inner: Debug)]
#[derive_where(Default; Outer: Default, Inner: Default)]
pub struct ComposedConnector<Outer, Inner, Error> {
    outer_connector: Outer,
    inner_connector: Inner,
    /// The type of error returned by [`Connector::connect_over`].
    ///
    /// This lets us produce an error type that is distinct from the inner and
    /// outer `Connector` error types.
    _error: PhantomData<Error>,
}

impl<O, I, E> ComposedConnector<O, I, E> {
    pub fn new(outer: O, inner: I) -> Self {
        Self {
            outer_connector: outer,
            inner_connector: inner,
            _error: PhantomData,
        }
    }

    /// Consumes the composed connector and returns its consituents.
    pub fn into_connectors(self) -> (O, I) {
        (self.outer_connector, self.inner_connector)
    }

    pub fn connect_inner_then_outer<IR: Send, OR: Send, S: Send>(
        &self,
        transport: S,
        inner_route: IR,
        outer_route: OR,
        log_tag: Arc<str>,
    ) -> impl Future<Output = Result<O::Connection, E>> + Send + use<'_, IR, OR, S, I, O, E>
    where
        O: Connector<OR, I::Connection, Error: Into<E>> + Sync,
        I: Connector<IR, S, Error: Into<E>> + Sync,
    {
        let Self {
            inner_connector,
            outer_connector,
            _error,
        } = self;
        async move {
            let inner_connected = inner_connector
                .connect_over(transport, inner_route, log_tag.clone())
                .await
                .map_err(Into::into)?;
            outer_connector
                .connect_over(inner_connected, outer_route, log_tag)
                .await
                .map_err(Into::into)
        }
    }
}
