//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::time::Duration;

use async_trait::async_trait;
use http::HeaderName;
use libsignal_net_infra::dns::DnsResolver;
use libsignal_net_infra::route::DirectOrProxyProvider;
use libsignal_net_infra::testutil::no_network_change_events;
use libsignal_net_infra::utils::NetworkChangeEvent;
use libsignal_net_infra::EnableDomainFronting;

use crate::auth::Auth;
use crate::connect_state::{ConnectState, ConnectionResources, SUGGESTED_CONNECT_CONFIG};
use crate::enclave::{self, EnclaveEndpoint, NewHandshake, SvrBFlavor};
use crate::svr::SvrConnection;

const WS2_CONFIG: libsignal_net_infra::ws2::Config = libsignal_net_infra::ws2::Config {
    local_idle_timeout: Duration::from_secs(10),
    remote_idle_ping_timeout: Duration::from_secs(10),
    remote_idle_disconnect_timeout: Duration::from_secs(30),
};

/// This trait helps create direct SVRB connections for various combinations of
/// enclaves kinds.
#[async_trait]
pub trait DirectConnect {
    type ConnectionResults;

    async fn connect(&self, auth: &Auth) -> Self::ConnectionResults;
}

#[async_trait]
impl<A> DirectConnect for EnclaveEndpoint<'static, A>
where
    A: SvrBFlavor + NewHandshake + Sized + Send,
{
    type ConnectionResults = Result<SvrConnection<A>, enclave::Error>;

    async fn connect(&self, auth: &Auth) -> Self::ConnectionResults {
        connect_one(self, auth, &no_network_change_events()).await
    }
}

async fn connect_one<Enclave>(
    endpoint: &EnclaveEndpoint<'static, Enclave>,
    auth: &Auth,
    network_change_event: &NetworkChangeEvent,
) -> Result<SvrConnection<Enclave>, enclave::Error>
where
    Enclave: SvrBFlavor + NewHandshake + Sized,
{
    let confirmation_header_name = endpoint
        .domain_config
        .connect
        .confirmation_header_name
        .map(HeaderName::from_static);
    let connect_state = ConnectState::new(SUGGESTED_CONNECT_CONFIG);
    let resolver = DnsResolver::new(network_change_event);
    let connection_resources = ConnectionResources {
        connect_state: &connect_state,
        dns_resolver: &resolver,
        network_change_event,
        confirmation_header_name,
    };

    SvrConnection::connect(
        connection_resources,
        DirectOrProxyProvider::maybe_proxied(
            endpoint.enclave_websocket_provider(EnableDomainFronting::No),
            None,
        ),
        WS2_CONFIG,
        &endpoint.params,
        auth.clone(),
    )
    .await
}
