//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;
use std::time::{Duration, SystemTime};

use attest::svr2::RaftConfig;
use attest::{cds2, enclave, nitro, tpm2snp};
use derive_where::derive_where;
use http::uri::PathAndQuery;

use crate::auth::HttpBasicAuth;
use crate::env::{DomainConfig, Svr3Env};
use crate::infra::connection_manager::{
    ConnectionManager, MultiRouteConnectionManager, SingleRouteThrottlingConnectionManager,
};
use crate::infra::errors::LogSafeDisplay;
use crate::infra::reconnect::{ServiceConnectorWithDecorator, ServiceInitializer, ServiceState};
use crate::infra::ws::{
    AttestedConnection, AttestedConnectionError, WebSocketClientConnector, WebSocketConnectError,
    WebSocketServiceError,
};
use crate::infra::{
    make_ws_config, AsyncDuplexStream, ConnectionParams, EndpointConnection, TransportConnector,
};
use crate::svr::SvrConnection;

pub trait EnclaveKind {
    fn url_path(enclave: &[u8]) -> PathAndQuery;
}
pub trait Svr3Flavor: EnclaveKind {}

pub enum Cdsi {}

pub enum Sgx {}

pub enum Nitro {}

pub enum Tpm2Snp {}

impl EnclaveKind for Cdsi {
    fn url_path(enclave: &[u8]) -> PathAndQuery {
        PathAndQuery::try_from(format!("/v1/{}/discovery", hex::encode(enclave))).unwrap()
    }
}

impl EnclaveKind for Sgx {
    fn url_path(enclave: &[u8]) -> PathAndQuery {
        PathAndQuery::try_from(format!("/v1/{}", hex::encode(enclave))).unwrap()
    }
}

impl EnclaveKind for Nitro {
    fn url_path(enclave: &[u8]) -> PathAndQuery {
        PathAndQuery::try_from(format!(
            "/v1/{}",
            std::str::from_utf8(enclave).expect("valid utf8")
        ))
        .unwrap()
    }
}

impl EnclaveKind for Tpm2Snp {
    fn url_path(enclave: &[u8]) -> PathAndQuery {
        PathAndQuery::try_from(format!(
            "/v1/{}",
            std::str::from_utf8(enclave).expect("valid utf8")
        ))
        .unwrap()
    }
}

impl Svr3Flavor for Sgx {}

impl Svr3Flavor for Nitro {}

impl Svr3Flavor for Tpm2Snp {}

pub trait IntoConnections {
    type Stream;
    type Connections: ArrayIsh<AttestedConnection<Self::Stream>> + Send;
    fn into_connections(self) -> Self::Connections;
}

pub trait IntoAttestedConnection: Into<AttestedConnection<Self::Stream>> {
    type Stream: Send;
}

impl<A> IntoConnections for A
where
    A: IntoAttestedConnection,
{
    type Connections = [AttestedConnection<A::Stream>; 1];
    type Stream = A::Stream;
    fn into_connections(self) -> Self::Connections {
        [self.into()]
    }
}

impl<A, B> IntoConnections for (A, B)
where
    A: IntoAttestedConnection,
    B: IntoAttestedConnection<Stream = A::Stream>,
{
    type Connections = [AttestedConnection<A::Stream>; 2];
    type Stream = A::Stream;
    fn into_connections(self) -> Self::Connections {
        [self.0.into(), self.1.into()]
    }
}

impl<A, B, C> IntoConnections for (A, B, C)
where
    A: IntoAttestedConnection,
    B: IntoAttestedConnection<Stream = A::Stream>,
    C: IntoAttestedConnection<Stream = A::Stream>,
{
    type Connections = [AttestedConnection<A::Stream>; 3];
    type Stream = A::Stream;
    fn into_connections(self) -> Self::Connections {
        [self.0.into(), self.1.into(), self.2.into()]
    }
}

pub trait ArrayIsh<T>: AsRef<[T]> + AsMut<[T]> {
    const N: usize;
}

impl<T, const N: usize> ArrayIsh<T> for [T; N] {
    const N: usize = N;
}

pub trait PpssSetup<S> {
    type Connections: IntoConnections<Stream = S> + Send;
    type ServerIds: ArrayIsh<u64> + Send;
    const N: usize = Self::ServerIds::N;
    fn server_ids() -> Self::ServerIds;
}

impl<S: Send> PpssSetup<S> for Svr3Env<'_> {
    type Connections = (
        SvrConnection<Sgx, S>,
        SvrConnection<Nitro, S>,
        SvrConnection<Tpm2Snp, S>,
    );
    type ServerIds = [u64; 3];

    fn server_ids() -> Self::ServerIds {
        [1, 2, 3]
    }
}

#[derive_where(Clone, Copy; Bytes)]
pub struct MrEnclave<Bytes, E> {
    inner: Bytes,
    enclave_kind: PhantomData<E>,
}

impl<Bytes, E: EnclaveKind> MrEnclave<Bytes, E> {
    pub const fn new(bytes: Bytes) -> Self {
        Self {
            inner: bytes,
            enclave_kind: PhantomData,
        }
    }
}

impl<Bytes: AsRef<[u8]>, S> AsRef<[u8]> for MrEnclave<Bytes, S> {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

#[derive_where(Copy, Clone)]
pub struct EnclaveEndpoint<'a, E: EnclaveKind> {
    pub domain_config: DomainConfig,
    pub mr_enclave: MrEnclave<&'a [u8], E>,
}

pub trait NewHandshake {
    fn new_handshake(
        params: &EndpointParams<Self>,
        attestation_message: &[u8],
    ) -> enclave::Result<enclave::Handshake>
    where
        Self: EnclaveKind + Sized;
}

pub struct EndpointParams<E: EnclaveKind> {
    pub(crate) mr_enclave: MrEnclave<&'static [u8], E>,
    pub(crate) raft_config_override: Option<&'static RaftConfig>,
}

impl<E: EnclaveKind> EndpointParams<E> {
    pub const fn new(mr_enclave: MrEnclave<&'static [u8], E>) -> Self {
        Self {
            mr_enclave,
            raft_config_override: None,
        }
    }

    pub fn with_raft_override(mut self, raft_config: &'static RaftConfig) -> Self {
        self.raft_config_override = Some(raft_config);
        self
    }
}

pub struct EnclaveEndpointConnection<E: EnclaveKind, C> {
    pub(crate) endpoint_connection: EndpointConnection<C>,
    pub(crate) params: EndpointParams<E>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum Error {
    /// websocket error: {0}
    WebSocketConnect(#[from] WebSocketConnectError),
    /// Network error: {0}
    WebSocket(#[from] WebSocketServiceError),
    /// Protocol error after establishing a connection
    Protocol,
    /// Enclave attestation failed: {0}
    AttestationError(attest::enclave::Error),
    /// Connection timeout
    ConnectionTimedOut,
}

impl LogSafeDisplay for Error {}

impl From<AttestedConnectionError> for Error {
    fn from(value: AttestedConnectionError) -> Self {
        match value {
            AttestedConnectionError::ClientConnection(_) => Self::Protocol,
            AttestedConnectionError::WebSocket(net) => Self::WebSocket(net),
            AttestedConnectionError::Protocol => Self::Protocol,
            AttestedConnectionError::Sgx(err) => Self::AttestationError(err),
        }
    }
}

impl<E: EnclaveKind + NewHandshake, C: ConnectionManager> EnclaveEndpointConnection<E, C> {
    pub(crate) async fn connect<S: AsyncDuplexStream, T: TransportConnector<Stream = S>>(
        &self,
        auth: impl HttpBasicAuth,
        transport_connector: T,
    ) -> Result<AttestedConnection<S>, Error>
    where
        C: ConnectionManager,
    {
        let auth_decorator = auth.into();
        let connector = ServiceConnectorWithDecorator::new(
            WebSocketClientConnector::<_, WebSocketServiceError>::new(
                transport_connector,
                self.endpoint_connection.config.clone(),
            ),
            auth_decorator,
        );
        let service_initializer =
            ServiceInitializer::new(connector, &self.endpoint_connection.manager);
        let connection_attempt_result = service_initializer.connect().await;
        let websocket = match connection_attempt_result {
            ServiceState::Active(websocket, _) => Ok(websocket),
            ServiceState::Cooldown(_) => {
                unreachable!("new service connector should not be in cooldown")
            }
            ServiceState::Error(e) => Err(Error::WebSocketConnect(e)),
            ServiceState::ConnectionTimedOut => Err(Error::ConnectionTimedOut),
            ServiceState::Inactive => {
                unreachable!("can't be returned by the initializer")
            }
        }?;
        let attested = AttestedConnection::connect(websocket, |attestation_msg| {
            E::new_handshake(&self.params, attestation_msg)
        })
        .await?;

        Ok(attested)
    }
}

impl<E: EnclaveKind> EnclaveEndpointConnection<E, SingleRouteThrottlingConnectionManager> {
    pub fn new(endpoint: EnclaveEndpoint<'static, E>, connect_timeout: Duration) -> Self {
        Self::with_custom_properties(endpoint, connect_timeout, None)
    }

    pub fn with_custom_properties(
        endpoint: EnclaveEndpoint<'static, E>,
        connect_timeout: Duration,
        raft_config_override: Option<&'static RaftConfig>,
    ) -> Self {
        Self {
            endpoint_connection: EndpointConnection {
                manager: SingleRouteThrottlingConnectionManager::new(
                    endpoint.domain_config.connection_params(),
                    connect_timeout,
                ),
                config: make_ws_config(E::url_path(endpoint.mr_enclave.as_ref()), connect_timeout),
            },
            params: EndpointParams {
                mr_enclave: endpoint.mr_enclave,
                raft_config_override,
            },
        }
    }
}

impl<E: EnclaveKind> EnclaveEndpointConnection<E, MultiRouteConnectionManager> {
    pub fn new_multi(
        mr_enclave: MrEnclave<&'static [u8], E>,
        connection_params: impl IntoIterator<Item = ConnectionParams>,
        connect_timeout: Duration,
    ) -> Self {
        Self {
            endpoint_connection: EndpointConnection::new_multi(
                connection_params,
                connect_timeout,
                make_ws_config(E::url_path(mr_enclave.as_ref()), connect_timeout),
            ),
            params: EndpointParams {
                mr_enclave,
                raft_config_override: None,
            },
        }
    }
}

impl NewHandshake for Sgx {
    fn new_handshake(
        params: &EndpointParams<Self>,
        attestation_message: &[u8],
    ) -> enclave::Result<enclave::Handshake> {
        attest::svr2::new_handshake_with_override(
            params.mr_enclave.as_ref(),
            attestation_message,
            SystemTime::now(),
            params.raft_config_override,
        )
    }
}

impl NewHandshake for Cdsi {
    fn new_handshake(
        params: &EndpointParams<Self>,
        attestation_message: &[u8],
    ) -> enclave::Result<enclave::Handshake> {
        cds2::new_handshake(
            params.mr_enclave.as_ref(),
            attestation_message,
            SystemTime::now(),
        )
    }
}

impl NewHandshake for Nitro {
    fn new_handshake(
        params: &EndpointParams<Self>,
        attestation_message: &[u8],
    ) -> enclave::Result<enclave::Handshake> {
        nitro::new_handshake(
            params.mr_enclave.as_ref(),
            attestation_message,
            SystemTime::now(),
            params.raft_config_override,
        )
    }
}

impl NewHandshake for Tpm2Snp {
    fn new_handshake(
        params: &EndpointParams<Self>,
        attestation_message: &[u8],
    ) -> enclave::Result<enclave::Handshake> {
        tpm2snp::new_handshake(
            params.mr_enclave.as_ref(),
            attestation_message,
            SystemTime::now(),
        )
    }
}
