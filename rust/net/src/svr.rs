//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;

use crate::auth::HttpBasicAuth;
use crate::enclave::{EnclaveEndpointConnection, NewHandshake, Svr3Flavor};
use crate::infra::connection_manager::ConnectionManager;
use crate::infra::ws::{AttestedConnection, DefaultStream};
use crate::infra::{AsyncDuplexStream, TransportConnector};

pub use crate::enclave::Error;

pub struct SvrConnection<Flavor: Svr3Flavor, S = DefaultStream> {
    inner: AttestedConnection<S>,
    witness: PhantomData<Flavor>,
}

impl<Flavor: Svr3Flavor> From<SvrConnection<Flavor>> for AttestedConnection {
    fn from(conn: SvrConnection<Flavor>) -> Self {
        conn.inner
    }
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
