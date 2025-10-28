//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::future::Future;

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
pub struct ComposedConnector<Outer, Inner> {
    outer_connector: Outer,
    inner_connector: Inner,
}

impl<O, I> ComposedConnector<O, I> {
    pub fn new(outer: O, inner: I) -> Self {
        Self {
            outer_connector: outer,
            inner_connector: inner,
        }
    }

    /// Consumes the composed connector and returns its consituents.
    pub fn into_connectors(self) -> (O, I) {
        (self.outer_connector, self.inner_connector)
    }

    pub fn connect_inner_then_outer<'a, IR: Send, OR: Send, S: Send>(
        &self,
        transport: S,
        inner_route: IR,
        outer_route: OR,
        log_tag: &'a str,
    ) -> impl Future<Output = Result<O::Connection, O::Error>> + Send + use<'_, 'a, IR, OR, S, I, O>
    where
        O: Connector<OR, I::Connection> + Sync,
        // We use Into rather than From for the errors because the outer error is more likely to be
        // a concrete type.
        I: Connector<IR, S, Error: Into<O::Error>> + Sync,
    {
        let Self {
            inner_connector,
            outer_connector,
        } = self;
        async move {
            let inner_connected = inner_connector
                .connect_over(transport, inner_route, log_tag)
                .await
                .map_err(Into::into)?;
            outer_connector
                .connect_over(inner_connected, outer_route, log_tag)
                .await
        }
    }
}
