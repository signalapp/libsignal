//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::time::Duration;

use async_trait::async_trait;
use libsignal_net_infra::dns::DnsResolver;
use libsignal_net_infra::tcp_ssl::DirectConnector;
use libsignal_net_infra::utils::ObservableEvent;
use libsignal_net_infra::ws::DefaultStream;
use libsignal_net_infra::TransportConnector;

use crate::auth::Auth;
use crate::enclave;
use crate::enclave::{EnclaveEndpoint, EnclaveEndpointConnection, NewHandshake, Svr3Flavor};
use crate::svr::SvrConnection;

const DIRECT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

/// This trait helps create direct SVR3 connections for various combinations of
/// enclaves kinds.
#[async_trait]
pub trait DirectConnect {
    type ConnectionResults;

    async fn connect(&self, auth: &Auth) -> Self::ConnectionResults;
}

#[async_trait]
impl<A> DirectConnect for EnclaveEndpoint<'static, A>
where
    A: Svr3Flavor + NewHandshake + Sized + Send,
{
    type ConnectionResults = Result<SvrConnection<A>, enclave::Error>;

    async fn connect(&self, auth: &Auth) -> Self::ConnectionResults {
        let network_change_event = ObservableEvent::default();
        let transport = default_transport(&network_change_event);
        connect_one(self, auth, transport, &network_change_event).await
    }
}

#[async_trait]
impl<A, B> DirectConnect for (&EnclaveEndpoint<'static, A>, &EnclaveEndpoint<'static, B>)
where
    A: Svr3Flavor + NewHandshake + Sized + Send,
    B: Svr3Flavor + NewHandshake + Sized + Send,
{
    type ConnectionResults = (
        Result<SvrConnection<A>, enclave::Error>,
        Result<SvrConnection<B>, enclave::Error>,
    );

    async fn connect(&self, auth: &Auth) -> Self::ConnectionResults {
        let network_change_event = ObservableEvent::default();
        let transport = default_transport(&network_change_event);
        futures_util::future::join(
            connect_one(self.0, auth, transport.clone(), &network_change_event),
            connect_one(self.1, auth, transport, &network_change_event),
        )
        .await
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
    type ConnectionResults = (
        Result<SvrConnection<A>, enclave::Error>,
        Result<SvrConnection<B>, enclave::Error>,
        Result<SvrConnection<C>, enclave::Error>,
    );

    async fn connect(&self, auth: &Auth) -> Self::ConnectionResults {
        let network_change_event = ObservableEvent::default();
        let transport = default_transport(&network_change_event);

        futures_util::future::join3(
            connect_one(self.0, auth, transport.clone(), &network_change_event),
            connect_one(self.1, auth, transport.clone(), &network_change_event),
            connect_one(self.2, auth, transport, &network_change_event),
        )
        .await
    }
}

fn default_transport(network_change_event: &ObservableEvent) -> DirectConnector {
    DirectConnector::new(DnsResolver::new(network_change_event))
}

async fn connect_one<Enclave, Transport>(
    endpoint: &EnclaveEndpoint<'static, Enclave>,
    auth: &Auth,
    connector: Transport,
    network_change_event: &ObservableEvent,
) -> Result<SvrConnection<Enclave>, enclave::Error>
where
    Enclave: Svr3Flavor + NewHandshake + Sized,
    Transport: TransportConnector<Stream = DefaultStream>,
{
    let ep_connection =
        EnclaveEndpointConnection::new(endpoint, DIRECT_CONNECTION_TIMEOUT, network_change_event);
    SvrConnection::connect(auth.clone(), &ep_connection, connector).await
}
