//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;

use derive_where::derive_where;
use futures_util::TryFutureExt as _;
use tokio_util::either::Either;

use crate::route::{Connector, DirectOrProxyRoute};

/// A [`Connector`] for [`DirectOrProxyRoute`] that delegates to direct or proxy
/// connectors.
#[derive_where(Debug; D: Debug, P: Debug)]
#[derive_where(Default; D: Default, P: Default)]
pub struct DirectOrProxy<D, P, E> {
    direct: D,
    proxy: P,
    _error: PhantomData<E>,
}

impl<D, P, E> DirectOrProxy<D, P, E> {
    pub fn new(direct: D, proxy: P) -> Self {
        Self {
            direct,
            proxy,
            _error: PhantomData,
        }
    }

    /// Consumes the composed connector and returns its consituents.
    pub fn into_connectors(self) -> (D, P) {
        (self.direct, self.proxy)
    }
}

/// Establishes a connection either directly or through a proxy.
///
/// Delegates to the respective wrapped connector: [`DirectOrProxy`]'s `direct`
/// for [`DirectOrProxyRoute::Direct`] and `proxy` for
/// [`DirectOrProxyRoute::Proxy`].
impl<D, P, DR, PR, Inner, Err> Connector<DirectOrProxyRoute<DR, PR>, Inner>
    for DirectOrProxy<D, P, Err>
where
    D: Connector<DR, Inner, Error: Into<Err>>,
    P: Connector<PR, Inner, Error: Into<Err>>,
{
    type Connection = Either<D::Connection, P::Connection>;

    type Error = Err;

    fn connect_over(
        &self,
        over: Inner,
        route: DirectOrProxyRoute<DR, PR>,
        log_tag: &str,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        match route {
            DirectOrProxyRoute::Direct(d) => Either::Left(
                self.direct
                    .connect_over(over, d, log_tag)
                    .map_ok(Either::Left)
                    .map_err(Into::into),
            ),
            DirectOrProxyRoute::Proxy(p) => Either::Right(
                self.proxy
                    .connect_over(over, p, log_tag)
                    .map_ok(Either::Right)
                    .map_err(Into::into),
            ),
        }
    }
}
