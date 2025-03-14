//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;

use http::HeaderName;
use libsignal_net_infra::dns::DnsResolver;
use libsignal_net_infra::route::{RouteProvider, UnresolvedWebsocketServiceRoute};
use libsignal_net_infra::ws2::attested::AttestedConnection;

use crate::auth::Auth;
use crate::connect_state::{ConnectState, RouteInfo, WebSocketTransportConnectorFactory};
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
        connect: &tokio::sync::RwLock<ConnectState<impl WebSocketTransportConnectorFactory>>,
        resolver: &DnsResolver,
        route_provider: impl RouteProvider<Route = UnresolvedWebsocketServiceRoute>,
        confirmation_header_name: Option<HeaderName>,
        ws_config: crate::infra::ws2::Config,
        params: &EndpointParams<'_, E>,
        auth: Auth,
    ) -> Result<Self, Error> {
        ConnectState::connect_attested_ws(
            connect,
            route_provider,
            auth,
            resolver,
            confirmation_header_name,
            (ws_config, crate::infra::ws::WithoutResponseHeaders::new()),
            format!("svr3:{}", std::any::type_name::<E>()).into(),
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
