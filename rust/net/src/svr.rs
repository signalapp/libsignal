//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;
use std::sync::Arc;

use libsignal_net_infra::connection_manager::ConnectionManager;
use libsignal_net_infra::host::Host;
use libsignal_net_infra::ws2::attested::AttestedConnection;
use libsignal_net_infra::TransportConnector;

use crate::auth::Auth;
pub use crate::enclave::Error;
use crate::enclave::{EnclaveEndpointConnection, IntoAttestedConnection, NewHandshake, Svr3Flavor};

pub struct SvrConnection<Flavor: Svr3Flavor> {
    inner: AttestedConnection,
    remote_address: Host<std::sync::Arc<str>>,
    witness: PhantomData<Flavor>,
}

impl<Flavor: Svr3Flavor> From<SvrConnection<Flavor>> for (AttestedConnection, Host<Arc<str>>) {
    fn from(conn: SvrConnection<Flavor>) -> Self {
        (conn.inner, conn.remote_address)
    }
}

impl<Flavor: Svr3Flavor> IntoAttestedConnection for SvrConnection<Flavor> {}

impl<E: Svr3Flavor> SvrConnection<E>
where
    E: Svr3Flavor + NewHandshake + Sized,
{
    pub async fn connect<C, T>(
        auth: Auth,
        connection: &EnclaveEndpointConnection<E, C>,
        transport_connector: T,
    ) -> Result<Self, Error>
    where
        C: ConnectionManager,
        T: TransportConnector,
    {
        connection
            .connect(auth, transport_connector)
            .await
            .map(|(connection, info)| Self {
                inner: connection,
                remote_address: info.address,
                witness: PhantomData,
            })
    }
}
