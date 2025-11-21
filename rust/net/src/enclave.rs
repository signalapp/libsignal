//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;
use std::time::SystemTime;

use attest::svr2::RaftConfig;
use attest::{cds2, enclave};
use derive_where::derive_where;
use http::uri::PathAndQuery;
use libsignal_net_infra::errors::{LogSafeDisplay, RetryLater};
use libsignal_net_infra::extract_retry_later;
use libsignal_net_infra::route::{
    DirectTcpRouteProvider, DomainFrontRouteProvider, HttpsProvider, TlsRouteProvider,
    WebSocketProvider, WebSocketRouteFragment,
};
use libsignal_net_infra::ws::attested::{
    AttestedConnection, AttestedConnectionError, AttestedProtocolError,
};
use libsignal_net_infra::ws::{self, WebSocketConnectError, WebSocketError};

use crate::env::{DomainConfig, SvrBEnv};
use crate::infra::{EnableDomainFronting, EnforceMinimumTls, OverrideNagleAlgorithm};
use crate::svr::SvrConnection;
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

pub trait SvrBFlavor: EnclaveKind {}

pub enum Cdsi {}

pub enum SvrSgx {}

impl EnclaveKind for Cdsi {
    type RaftConfigType = ();
    fn url_path(enclave: &[u8]) -> PathAndQuery {
        PathAndQuery::try_from(format!("/v1/{}/discovery", hex::encode(enclave)))
            .expect("valid path")
    }
}

impl EnclaveKind for SvrSgx {
    type RaftConfigType = &'static RaftConfig;
    fn url_path(enclave: &[u8]) -> PathAndQuery {
        PathAndQuery::try_from(format!("/v1/{}", hex::encode(enclave))).expect("valid path")
    }
}

impl SvrBFlavor for SvrSgx {}

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

pub trait PpssSetup {
    type ConnectionResults: IntoConnectionResults + Send;
    type ServerIds: ArrayIsh<u64> + Send;
    const N: usize = Self::ServerIds::N;
    fn server_ids() -> Self::ServerIds;
}

impl PpssSetup for SvrBEnv<'_> {
    type ConnectionResults = Result<SvrConnection<SvrSgx>, Error>;
    type ServerIds = [u64; 1];

    fn server_ids() -> Self::ServerIds {
        [1]
    }
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
    pub ws_config: ws::Config,
    pub params: EndpointParams<'a, E>,
}

pub trait NewHandshake: EnclaveKind + Sized {
    fn new_handshake(
        params: &EndpointParams<Self>,
        attestation_message: &[u8],
    ) -> enclave::Result<enclave::Handshake>;
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum Error {
    /// Websocket error: {0}
    WebSocketConnect(WebSocketConnectError),
    /// {0}
    RateLimited(RetryLater),
    /// Network error: {0}
    WebSocket(#[from] WebSocketError),
    /// Protocol error after establishing a connection: {0}
    Protocol(AttestedProtocolError),
    /// Enclave attestation failed: {0}
    AttestationError(attest::enclave::Error),
    /// No connection attempts succeeded before timeout
    AllConnectionAttemptsFailed,
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

impl From<WebSocketServiceConnectError> for Error {
    fn from(value: WebSocketServiceConnectError) -> Self {
        match value {
            WebSocketServiceConnectError::RejectedByServer {
                response,
                received_at: _,
            } => {
                if response.status() == http::StatusCode::TOO_MANY_REQUESTS {
                    if let Some(retry_later) = extract_retry_later(response.headers()) {
                        return Self::RateLimited(retry_later);
                    }
                }
                Self::WebSocket(WebSocketError::Http(response))
            }
            WebSocketServiceConnectError::Connect(e, _) => Self::WebSocketConnect(e),
        }
    }
}

impl<E: EnclaveKind> EnclaveEndpoint<'_, E> {
    pub fn enclave_websocket_provider(
        &self,
        enable_domain_fronting: EnableDomainFronting,
    ) -> WebSocketProvider<
        HttpsProvider<DomainFrontRouteProvider, TlsRouteProvider<DirectTcpRouteProvider>>,
    > {
        let Self {
            domain_config,
            ws_config: _,
            params,
        } = self;
        let http_provider = domain_config.connect.route_provider(
            enable_domain_fronting,
            OverrideNagleAlgorithm::UseSystemDefault,
        );

        let ws_fragment = WebSocketRouteFragment {
            ws_config: Default::default(),
            endpoint: E::url_path(params.mr_enclave.as_ref()),
            headers: Default::default(),
        };

        WebSocketProvider::new(ws_fragment, http_provider)
    }

    pub fn enclave_websocket_provider_with_options(
        &self,
        enable_domain_fronting: EnableDomainFronting,
        enforce_minimum_tls: EnforceMinimumTls,
        override_nagle_algorithm: OverrideNagleAlgorithm,
    ) -> WebSocketProvider<
        HttpsProvider<DomainFrontRouteProvider, TlsRouteProvider<DirectTcpRouteProvider>>,
    > {
        let Self {
            domain_config,
            ws_config: _,
            params,
        } = self;
        let http_provider = domain_config.connect.route_provider_with_options(
            enable_domain_fronting,
            enforce_minimum_tls,
            override_nagle_algorithm,
        );

        let ws_fragment = WebSocketRouteFragment {
            ws_config: Default::default(),
            endpoint: E::url_path(params.mr_enclave.as_ref()),
            headers: Default::default(),
        };

        WebSocketProvider::new(ws_fragment, http_provider)
    }
}

impl NewHandshake for SvrSgx {
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
