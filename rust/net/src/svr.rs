//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;

use libsignal_net_infra::connection_manager::ConnectionManager;
use libsignal_net_infra::ws::AttestedConnection;
use libsignal_net_infra::{AsyncDuplexStream, HttpBasicAuth, TransportConnector};

pub use crate::enclave::Error;
use crate::enclave::{EnclaveEndpointConnection, IntoAttestedConnection, NewHandshake, Svr3Flavor};

pub struct SvrConnection<Flavor: Svr3Flavor, S> {
    inner: AttestedConnection<S>,
    witness: PhantomData<Flavor>,
}

impl<Flavor: Svr3Flavor, S> From<SvrConnection<Flavor, S>> for AttestedConnection<S> {
    fn from(conn: SvrConnection<Flavor, S>) -> Self {
        conn.inner
    }
}

impl<Flavor: Svr3Flavor, S: Send> IntoAttestedConnection for SvrConnection<Flavor, S> {
    type Stream = S;
}

impl<E: Svr3Flavor, S: AsyncDuplexStream> SvrConnection<E, S>
where
    E: Svr3Flavor + NewHandshake + Sized,
    S: AsyncDuplexStream,
{
    pub async fn connect<C, T>(
        auth: impl HttpBasicAuth,
        connection: &EnclaveEndpointConnection<E, C>,
        transport_connector: T,
    ) -> Result<Self, Error>
    where
        C: ConnectionManager,
        T: TransportConnector<Stream = S>,
    {
        connection
            .connect(auth, transport_connector)
            .await
            .map(|inner| Self {
                inner,
                witness: PhantomData,
            })
    }
}
