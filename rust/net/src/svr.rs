//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;

use thiserror::Error;

use crate::auth::HttpBasicAuth;
use crate::enclave::{EndpointConnection, NewHandshake, Svr3Flavor};
use crate::infra::connection_manager::ConnectionManager;
use crate::infra::errors::NetError;
use crate::infra::reconnect::{ServiceConnectorWithDecorator, ServiceInitializer, ServiceState};
use crate::infra::ws::{AttestedConnection, AttestedConnectionError, DefaultStream};
use crate::infra::{AsyncDuplexStream, TransportConnector};

#[derive(Debug, Error, displaydoc::Display)]
pub enum Error {
    /// Network error
    Net(#[from] NetError),
    /// Protocol error after establishing a connection.
    Protocol,
    /// SGX attestation failed.
    AttestationError(String),
}

impl From<AttestedConnectionError> for Error {
    fn from(value: AttestedConnectionError) -> Self {
        match value {
            AttestedConnectionError::ClientConnection(_) => Self::Protocol,
            AttestedConnectionError::Net(net) => Self::Net(net),
            AttestedConnectionError::Protocol => Self::Protocol,
            AttestedConnectionError::Sgx(err) => Self::AttestationError(err.to_string()),
        }
    }
}

pub struct SvrConnection<Flavor: Svr3Flavor, S = DefaultStream> {
    inner: AttestedConnection<S>,
    witness: PhantomData<Flavor>,
}

impl<Flavor: Svr3Flavor> From<SvrConnection<Flavor>> for AttestedConnection {
    fn from(conn: SvrConnection<Flavor>) -> Self {
        conn.inner
    }
}

impl<Flavor: Svr3Flavor, S> SvrConnection<Flavor, S> {
    pub fn new(inner: AttestedConnection<S>) -> Self {
        Self {
            inner,
            witness: PhantomData,
        }
    }
}

impl<E: Svr3Flavor, S: AsyncDuplexStream> SvrConnection<E, S>
where
    E: Svr3Flavor + NewHandshake + Sized,
    S: AsyncDuplexStream,
{
    pub async fn connect<C, T>(
        auth: impl HttpBasicAuth,
        connection: &EndpointConnection<E, C, T>,
    ) -> Result<Self, Error>
    where
        C: ConnectionManager,
        T: TransportConnector<Stream = S>,
    {
        // TODO: This is almost a direct copy of CdsiConnection::connect. They can be unified.
        let auth_decorator = auth.into();
        let connector = ServiceConnectorWithDecorator::new(&connection.connector, auth_decorator);
        let service_initializer = ServiceInitializer::new(&connector, &connection.manager);
        let connection_attempt_result = service_initializer.connect().await;
        let websocket = match connection_attempt_result {
            ServiceState::Active(websocket, _) => Ok(websocket),
            ServiceState::Cooldown(_) => Err(Error::Net(NetError::NoServiceConnection)),
            ServiceState::Error(e) => Err(Error::Net(e)),
            ServiceState::TimedOut => Err(Error::Net(NetError::Timeout)),
        }?;
        let attested = AttestedConnection::connect(websocket, |attestation_msg| {
            E::new_handshake(&connection.params, attestation_msg)
        })
        .await?;

        Ok(Self::new(attested))
    }
}
