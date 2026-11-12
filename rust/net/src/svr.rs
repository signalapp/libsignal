//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net_infra::route::{RouteProvider, UnresolvedWebsocketServiceRoute};
use libsignal_net_infra::ws::attested::AttestedConnection;

use crate::auth::Auth;
use crate::connect_state::{
    ConnectionResources, RouteInfo, ServiceName, WebSocketTransportConnectorFactory,
};
pub use crate::enclave::Error;
use crate::enclave::{
    ConnectionLabel, EndpointParams, IntoAttestedConnection, LabeledConnection, NewHandshake,
};

pub struct SvrConnection {
    inner: AttestedConnection,
    remote_address: RouteInfo,
}

impl IntoAttestedConnection for SvrConnection {
    fn into_labeled_connection(self) -> LabeledConnection {
        let label = ConnectionLabel::from_log_safe(self.remote_address.to_string());
        let connection = self.inner;
        (connection, label)
    }
}

impl SvrConnection {
    pub async fn connect<E: NewHandshake>(
        connection_resources: ConnectionResources<'_, impl WebSocketTransportConnectorFactory>,
        service: ServiceName,
        route_provider: impl RouteProvider<Route = UnresolvedWebsocketServiceRoute>,
        ws_config: crate::infra::ws::Config,
        params: &EndpointParams<'_, E>,
        auth: &Auth,
    ) -> Result<Self, Error> {
        Self::connect_any(
            connection_resources,
            service,
            route_provider,
            ws_config,
            move |attestation_message| E::new_handshake(params, attestation_message),
            auth,
        )
        .await
    }

    pub async fn connect_any(
        connection_resources: ConnectionResources<'_, impl WebSocketTransportConnectorFactory>,
        service: ServiceName,
        route_provider: impl RouteProvider<Route = UnresolvedWebsocketServiceRoute>,
        ws_config: crate::infra::ws::Config,
        new_handshake: impl FnOnce(&[u8]) -> attest::enclave::Result<attest::enclave::Handshake>,
        auth: &Auth,
    ) -> Result<Self, Error> {
        connection_resources
            .connect_attested_ws(
                service,
                route_provider,
                auth,
                ws_config,
                "svr".into(),
                new_handshake,
            )
            .await
            .map(|(connection, info)| Self {
                inner: connection,
                remote_address: info,
            })
    }
}
