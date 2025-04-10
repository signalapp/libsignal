//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;
use std::time::{Duration, SystemTime};

use attest::svr2::RaftConfig;
use attest::{cds2, enclave};
use derive_where::derive_where;
use http::uri::PathAndQuery;
use libsignal_net_infra::connection_manager::{
    MultiRouteConnectionManager, SingleRouteThrottlingConnectionManager,
};
use libsignal_net_infra::errors::LogSafeDisplay;
use libsignal_net_infra::route::{
    DirectTcpRouteProvider, DomainFrontRouteProvider, HttpsProvider, TlsRouteProvider,
    WebSocketProvider, WebSocketRouteFragment,
};
use libsignal_net_infra::utils::NetworkChangeEvent;
use libsignal_net_infra::ws::WebSocketServiceError;
use libsignal_net_infra::ws2::attested::{
    AttestedConnection, AttestedConnectionError, AttestedProtocolError,
};
use libsignal_net_infra::{make_ws_config, ConnectionParams, EndpointConnection};

use crate::env::DomainConfig;
use crate::infra::EnableDomainFronting;
use crate::ws::WebSocketServiceConnectError;

pub trait AsRaftConfig<'a> {
    fn as_raft_config(&self) -> Option<&'a RaftConfig>;
}

impl<'a> AsRaftConfig<'a> for () {
    fn as_raft_config(&self) -> Option<&'a RaftConfig> {
        None
    }
}

impl<'a> AsRaftConfig<'a> for &'a RaftConfig {
    fn as_raft_config(&self) -> Option<&'a RaftConfig> {
        Some(self)
    }
}

pub trait EnclaveKind {
    type RaftConfigType: AsRaftConfig<'static> + Clone + Sync + Send;
    fn url_path(enclave: &[u8]) -> PathAndQuery;
}

pub enum Cdsi {}

pub enum SgxPreQuantum {}

impl EnclaveKind for Cdsi {
    type RaftConfigType = ();
    fn url_path(enclave: &[u8]) -> PathAndQuery {
        PathAndQuery::try_from(format!("/v1/{}/discovery", hex::encode(enclave))).unwrap()
    }
}

impl EnclaveKind for SgxPreQuantum {
    type RaftConfigType = &'static RaftConfig;
    fn url_path(enclave: &[u8]) -> PathAndQuery {
        PathAndQuery::try_from(format!("/v1/{}", hex::encode(enclave))).unwrap()
    }
}

/// Log-safe human-readable label for a connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionLabel(String);

pub type LabeledConnection = (AttestedConnection, ConnectionLabel);

pub trait IntoConnectionResults {
    type ConnectionResults: ArrayIsh<Result<LabeledConnection, Error>> + Send;
    fn into_connection_results(self) -> Self::ConnectionResults;
}

/// Provides an [`AttestedConnection`] with a label for logging.
///
/// This trait provides useful indirection by allowing us to implement
/// [`IntoConnectionResults`] for heterogeneous tuples with types that implement
/// this trait.
pub trait IntoAttestedConnection {
    fn into_labeled_connection(self) -> LabeledConnection;
}

impl IntoAttestedConnection for LabeledConnection {
    fn into_labeled_connection(self) -> LabeledConnection {
        self
    }
}

impl<A> IntoConnectionResults for Result<A, Error>
where
    A: IntoAttestedConnection,
{
    type ConnectionResults = [Result<LabeledConnection, Error>; 1];
    fn into_connection_results(self) -> Self::ConnectionResults {
        [self.map(IntoAttestedConnection::into_labeled_connection)]
    }
}

impl<A, B> IntoConnectionResults for (Result<A, Error>, Result<B, Error>)
where
    A: IntoAttestedConnection,
    B: IntoAttestedConnection,
{
    type ConnectionResults = [Result<LabeledConnection, Error>; 2];
    fn into_connection_results(self) -> Self::ConnectionResults {
        [
            self.0.map(IntoAttestedConnection::into_labeled_connection),
            self.1.map(IntoAttestedConnection::into_labeled_connection),
        ]
    }
}

impl<A, B, C> IntoConnectionResults for (Result<A, Error>, Result<B, Error>, Result<C, Error>)
where
    A: IntoAttestedConnection,
    B: IntoAttestedConnection,
    C: IntoAttestedConnection,
{
    type ConnectionResults = [Result<LabeledConnection, Error>; 3];
    fn into_connection_results(self) -> Self::ConnectionResults {
        [
            self.0.map(IntoAttestedConnection::into_labeled_connection),
            self.1.map(IntoAttestedConnection::into_labeled_connection),
            self.2.map(IntoAttestedConnection::into_labeled_connection),
        ]
    }
}

impl ConnectionLabel {
    pub fn from_log_safe(value: String) -> Self {
        Self(value)
    }
}

impl LogSafeDisplay for ConnectionLabel {}
impl std::fmt::Display for ConnectionLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub trait ArrayIsh<T>: AsRef<[T]> + IntoIterator<Item = T> {
    const N: usize;
}

impl<T, const N: usize> ArrayIsh<T> for [T; N] {
    const N: usize = N;
}

#[derive_where(Clone, Copy; Bytes)]
pub struct MrEnclave<Bytes, E> {
    inner: Bytes,
    // Using fn instead of E directly so that `MrEnclave` implements `Send +
    // Sync` even if `E` does not.
    enclave_kind: PhantomData<fn(E) -> E>,
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

#[derive_where(Clone)]
pub struct EndpointParams<'a, E: EnclaveKind> {
    pub mr_enclave: MrEnclave<&'a [u8], E>,
    pub raft_config: E::RaftConfigType,
}

#[derive_where(Clone)]
pub struct EnclaveEndpoint<'a, E: EnclaveKind> {
    pub domain_config: DomainConfig,
    pub params: EndpointParams<'a, E>,
}

pub trait NewHandshake: EnclaveKind + Sized {
    fn new_handshake(
        params: &EndpointParams<Self>,
        attestation_message: &[u8],
    ) -> enclave::Result<enclave::Handshake>;
}

pub struct EnclaveEndpointConnection<E: EnclaveKind, C> {
    pub(crate) endpoint_connection: EndpointConnection<C>,
    #[allow(unused)]
    pub(crate) params: EndpointParams<'static, E>,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum Error {
    /// websocket error: {0}
    WebSocketConnect(#[from] WebSocketServiceConnectError),
    /// Network error: {0}
    WebSocket(#[from] WebSocketServiceError),
    /// Protocol error after establishing a connection: {0}
    Protocol(AttestedProtocolError),
    /// Enclave attestation failed: {0}
    AttestationError(attest::enclave::Error),
    /// Connection timeout
    ConnectionTimedOut,
}

impl LogSafeDisplay for Error {}

impl From<AttestedConnectionError> for Error {
    fn from(value: AttestedConnectionError) -> Self {
        match value {
            AttestedConnectionError::WebSocket(net) => Self::WebSocket(net),
            AttestedConnectionError::Protocol(error) => Self::Protocol(error),
            AttestedConnectionError::Attestation(err) => Self::AttestationError(err),
        }
    }
}

impl<E: EnclaveKind, C> EnclaveEndpointConnection<E, C> {
    pub fn ws2_config(&self) -> libsignal_net_infra::ws2::Config {
        self.endpoint_connection.config.ws2_config()
    }
}

impl<E: EnclaveKind> EnclaveEndpoint<'_, E> {
    pub fn route_provider(
        &self,
        enable_domain_fronting: EnableDomainFronting,
    ) -> WebSocketProvider<
        HttpsProvider<DomainFrontRouteProvider, TlsRouteProvider<DirectTcpRouteProvider>>,
    > {
        let Self {
            domain_config,
            params,
        } = self;
        let http_provider = domain_config.connect.route_provider(enable_domain_fronting);

        let ws_fragment = WebSocketRouteFragment {
            ws_config: Default::default(),
            endpoint: E::url_path(params.mr_enclave.as_ref()),
            headers: Default::default(),
        };

        WebSocketProvider::new(ws_fragment, http_provider)
    }
}

impl<E: EnclaveKind> EnclaveEndpointConnection<E, SingleRouteThrottlingConnectionManager> {
    pub fn new(
        endpoint: &EnclaveEndpoint<'static, E>,
        connect_timeout: Duration,
        network_change_event: &NetworkChangeEvent,
    ) -> Self {
        Self {
            endpoint_connection: EndpointConnection {
                manager: SingleRouteThrottlingConnectionManager::new(
                    endpoint.domain_config.connect.direct_connection_params(),
                    connect_timeout,
                    network_change_event,
                ),
                config: make_ws_config(
                    E::url_path(endpoint.params.mr_enclave.as_ref()),
                    connect_timeout,
                ),
            },
            params: endpoint.params.clone(),
        }
    }
}

impl<E: EnclaveKind> EnclaveEndpointConnection<E, MultiRouteConnectionManager> {
    pub fn new_multi(
        endpoint: &EnclaveEndpoint<'static, E>,
        connection_params: impl IntoIterator<Item = ConnectionParams>,
        one_route_connect_timeout: Duration,
        network_change_event: &NetworkChangeEvent,
    ) -> Self {
        Self {
            endpoint_connection: EndpointConnection::new_multi(
                connection_params,
                one_route_connect_timeout,
                make_ws_config(
                    E::url_path(endpoint.params.mr_enclave.as_ref()),
                    one_route_connect_timeout,
                ),
                network_change_event,
            ),
            params: endpoint.params.clone(),
        }
    }
}

impl NewHandshake for SgxPreQuantum {
    fn new_handshake(
        params: &EndpointParams<Self>,
        attestation_message: &[u8],
    ) -> enclave::Result<enclave::Handshake> {
        attest::svr2::new_handshake(
            params.mr_enclave.as_ref(),
            attestation_message,
            SystemTime::now(),
            params
                .raft_config
                .as_raft_config()
                .expect("Raft config must be present for SGX"),
            enclave::HandshakeType::PreQuantum,
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
