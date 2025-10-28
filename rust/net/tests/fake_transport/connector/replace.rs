//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net_infra::route::{
    ComposedConnector, DirectOrProxy, LoggingConnector, StaticTcpTimeoutConnector,
    ThrottlingConnector, VariableTlsTimeoutConnector,
};

use super::FakeTransportConnector;

/// Replaces `self`'s [`Connector`]s with [`FakeTransportConnector`].
pub trait ReplaceStatelessConnectorsWithFake {
    /// The type after replacement.
    type Replacement;

    /// Consumes `self` and swaps out all "real" `Connector`s.
    fn replace_with_fake(self, fake: FakeTransportConnector) -> Self::Replacement;
}

impl<Outer, Inner> ReplaceStatelessConnectorsWithFake for ComposedConnector<Outer, Inner>
where
    Outer: ReplaceStatelessConnectorsWithFake,
    Inner: ReplaceStatelessConnectorsWithFake,
{
    type Replacement = ComposedConnector<Outer::Replacement, Inner::Replacement>;

    fn replace_with_fake(self, fake: FakeTransportConnector) -> Self::Replacement {
        let (outer, inner) = self.into_connectors();
        ComposedConnector::new(
            outer.replace_with_fake(fake.clone()),
            inner.replace_with_fake(fake),
        )
    }
}

impl<Inner, Outer, Error> ReplaceStatelessConnectorsWithFake
    for VariableTlsTimeoutConnector<Outer, Inner, Error>
where
    Outer: ReplaceStatelessConnectorsWithFake,
    Inner: ReplaceStatelessConnectorsWithFake,
{
    type Replacement = VariableTlsTimeoutConnector<Outer::Replacement, Inner::Replacement, Error>;

    fn replace_with_fake(self, fake: FakeTransportConnector) -> Self::Replacement {
        let (outer, inner, timeout) = self.into_connectors_and_min_timeout();
        VariableTlsTimeoutConnector::new(
            outer.replace_with_fake(fake.clone()),
            inner.replace_with_fake(fake),
            timeout,
        )
    }
}

impl<D, P, E> ReplaceStatelessConnectorsWithFake for DirectOrProxy<D, P, E>
where
    D: ReplaceStatelessConnectorsWithFake,
    P: ReplaceStatelessConnectorsWithFake,
{
    type Replacement = DirectOrProxy<D::Replacement, P::Replacement, E>;

    fn replace_with_fake(self, fake: FakeTransportConnector) -> Self::Replacement {
        let (direct, proxy) = self.into_connectors();
        DirectOrProxy::new(
            direct.replace_with_fake(fake.clone()),
            proxy.replace_with_fake(fake),
        )
    }
}

impl ReplaceStatelessConnectorsWithFake for libsignal_net::infra::tcp_ssl::proxy::StatelessProxied {
    type Replacement = FakeTransportConnector;

    fn replace_with_fake(self, fake: FakeTransportConnector) -> Self::Replacement {
        fake
    }
}

impl ReplaceStatelessConnectorsWithFake for libsignal_net::infra::tcp_ssl::StatelessTcp {
    type Replacement = FakeTransportConnector;

    fn replace_with_fake(self, fake: FakeTransportConnector) -> Self::Replacement {
        fake
    }
}

impl ReplaceStatelessConnectorsWithFake for libsignal_net::infra::tcp_ssl::StatelessTls {
    type Replacement = FakeTransportConnector;

    fn replace_with_fake(self, fake: FakeTransportConnector) -> Self::Replacement {
        fake
    }
}

impl<C: ReplaceStatelessConnectorsWithFake> ReplaceStatelessConnectorsWithFake
    for ThrottlingConnector<C>
{
    type Replacement = ThrottlingConnector<FakeTransportConnector>;

    fn replace_with_fake(self, fake: FakeTransportConnector) -> Self::Replacement {
        self.replace_connector(fake)
    }
}

impl<C: ReplaceStatelessConnectorsWithFake> ReplaceStatelessConnectorsWithFake
    for LoggingConnector<C>
{
    type Replacement = C::Replacement;

    fn replace_with_fake(self, fake: FakeTransportConnector) -> Self::Replacement {
        // Discard the logging for fake connections.
        self.into_inner().replace_with_fake(fake)
    }
}

impl<C: ReplaceStatelessConnectorsWithFake> ReplaceStatelessConnectorsWithFake
    for StaticTcpTimeoutConnector<C>
{
    type Replacement = StaticTcpTimeoutConnector<C::Replacement>;

    fn replace_with_fake(self, fake: FakeTransportConnector) -> Self::Replacement {
        let (inner, timeout) = self.into_connector_and_timeout();
        StaticTcpTimeoutConnector::new(inner.replace_with_fake(fake), timeout)
    }
}
