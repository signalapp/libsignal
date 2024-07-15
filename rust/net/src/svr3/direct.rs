//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::time::Duration;

use async_trait::async_trait;

use crate::auth::Auth;
use crate::enclave;
use crate::enclave::{EnclaveEndpoint, EnclaveEndpointConnection, NewHandshake, Svr3Flavor};
use crate::infra::tcp_ssl::DirectConnector;
use crate::infra::ws::DefaultStream;
use crate::infra::TransportConnector;
use crate::svr::SvrConnection;

const DIRECT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// This trait helps create direct SVR3 connections for various combinations of
/// enclaves kinds.
#[async_trait]
pub trait DirectConnect {
    type Connections;

    async fn connect(&self, auth: &Auth) -> Result<Self::Connections, enclave::Error>;
}

#[async_trait]
impl<A> DirectConnect for EnclaveEndpoint<'static, A>
where
    A: Svr3Flavor + NewHandshake + Sized + Send,
{
    type Connections = SvrConnection<A, DefaultStream>;

    async fn connect(&self, auth: &Auth) -> Result<Self::Connections, enclave::Error> {
        connect_one(self, auth, DirectConnector::default()).await
    }
}

#[async_trait]
impl<A, B> DirectConnect for (&EnclaveEndpoint<'static, A>, &EnclaveEndpoint<'static, B>)
where
    A: Svr3Flavor + NewHandshake + Sized + Send,
    B: Svr3Flavor + NewHandshake + Sized + Send,
{
    type Connections = (
        SvrConnection<A, DefaultStream>,
        SvrConnection<B, DefaultStream>,
    );

    async fn connect(&self, auth: &Auth) -> Result<Self::Connections, enclave::Error> {
        let transport = DirectConnector::default();
        let (a, b) = futures_util::future::join(
            connect_one(self.0, auth, transport.clone()),
            connect_one(self.1, auth, transport),
        )
        .await;
        Ok((a?, b?))
    }
}

#[async_trait]
impl<A, B, C> DirectConnect
    for (
        &EnclaveEndpoint<'static, A>,
        &EnclaveEndpoint<'static, B>,
        &EnclaveEndpoint<'static, C>,
    )
where
    A: Svr3Flavor + NewHandshake + Sized + Send,
    B: Svr3Flavor + NewHandshake + Sized + Send,
    C: Svr3Flavor + NewHandshake + Sized + Send,
{
    type Connections = (
        SvrConnection<A, DefaultStream>,
        SvrConnection<B, DefaultStream>,
        SvrConnection<C, DefaultStream>,
    );

    async fn connect(&self, auth: &Auth) -> Result<Self::Connections, enclave::Error> {
        let transport = DirectConnector::default();

        let (a, b, c) = futures_util::future::join3(
            connect_one(self.0, auth, transport.clone()),
            connect_one(self.1, auth, transport.clone()),
            connect_one(self.2, auth, transport),
        )
        .await;
        Ok((a?, b?, c?))
    }
}

async fn connect_one<Enclave, Transport>(
    endpoint: &EnclaveEndpoint<'static, Enclave>,
    auth: &Auth,
    connector: Transport,
) -> Result<SvrConnection<Enclave, DefaultStream>, enclave::Error>
where
    Enclave: Svr3Flavor + NewHandshake + Sized,
    Transport: TransportConnector<Stream = DefaultStream>,
{
    let ep_connection = EnclaveEndpointConnection::new(endpoint, DIRECT_CONNECTION_TIMEOUT);
    SvrConnection::connect(auth.clone(), &ep_connection, connector).await
}
