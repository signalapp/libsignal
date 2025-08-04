//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;

use libsignal_net_infra::route::{RouteProvider, UnresolvedWebsocketServiceRoute};
use libsignal_net_infra::ws::attested::AttestedConnection;

use crate::auth::Auth;
use crate::connect_state::{ConnectionResources, RouteInfo, WebSocketTransportConnectorFactory};
pub use crate::enclave::Error;
use crate::enclave::{
    ConnectionLabel, EnclaveKind, EndpointParams, IntoAttestedConnection, LabeledConnection,
    NewHandshake,
};

pub struct SvrConnection<Kind: EnclaveKind> {
    inner: AttestedConnection,
    remote_address: RouteInfo,
    witness: PhantomData<Kind>,
}

impl<Kind: EnclaveKind> IntoAttestedConnection for SvrConnection<Kind> {
    fn into_labeled_connection(self) -> LabeledConnection {
        let label = ConnectionLabel::from_log_safe(self.remote_address.to_string());
        let connection = self.inner;
        (connection, label)
    }
}

impl<E> SvrConnection<E>
where
    E: EnclaveKind + NewHandshake + Sized,
{
    pub async fn connect(
        connection_resources: ConnectionResources<'_, impl WebSocketTransportConnectorFactory>,
        route_provider: impl RouteProvider<Route = UnresolvedWebsocketServiceRoute>,
        ws_config: crate::infra::ws::Config,
        params: &EndpointParams<'_, E>,
        auth: &Auth,
    ) -> Result<Self, Error> {
        connection_resources
            .connect_attested_ws(
                route_provider,
                auth,
                ws_config,
                format!("svr:{}", std::any::type_name::<E>()).into(),
                params,
            )
            .await
            .map(|(connection, info)| Self {
                inner: connection,
                remote_address: info,
                witness: PhantomData,
            })
    }
}
