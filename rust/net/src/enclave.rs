//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use attest::svr2::RaftConfig;
use attest::{cds2, enclave, nitro, tpm2snp};
use derive_where::derive_where;
use http::uri::PathAndQuery;
use http::HeaderMap;
use libsignal_net_infra::connection_manager::{
    ConnectionManager, MultiRouteConnectionManager, SingleRouteThrottlingConnectionManager,
};
use libsignal_net_infra::errors::LogSafeDisplay;
use libsignal_net_infra::route::{
    DirectTcpRouteProvider, DomainFrontRouteProvider, HttpsProvider, TlsRouteProvider,
    WebSocketProvider, WebSocketRouteFragment,
};
use libsignal_net_infra::service::{ServiceInitializer, ServiceState};
use libsignal_net_infra::utils::ObservableEvent;
use libsignal_net_infra::ws::{WebSocketServiceError, WebSocketStreamConnector};
use libsignal_net_infra::ws2::attested::{
    AttestedConnection, AttestedConnectionError, AttestedProtocolError,
};
use libsignal_net_infra::{
    make_ws_config, AsHttpHeader as _, AsyncDuplexStream, ConnectionParams, EndpointConnection,
    ServiceConnectionInfo, TransportConnector,
};

use crate::auth::Auth;
use crate::env::{DomainConfig, Svr3Env};
use crate::infra::EnableDomainFronting;
use crate::svr::SvrConnection;
use crate::ws::{WebSocketServiceConnectError, WebSocketServiceConnector};

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

pub trait Svr3Flavor: EnclaveKind {}

pub enum Cdsi {}

pub enum SgxPreQuantum {}

pub enum Sgx {}

pub enum Nitro {}

pub enum Tpm2Snp {}

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

impl EnclaveKind for Sgx {
    type RaftConfigType = &'static RaftConfig;
    fn url_path(enclave: &[u8]) -> PathAndQuery {
        PathAndQuery::try_from(format!("/v1/{}", hex::encode(enclave))).unwrap()
    }
}

impl EnclaveKind for Nitro {
    type RaftConfigType = &'static RaftConfig;
    fn url_path(enclave: &[u8]) -> PathAndQuery {
        PathAndQuery::try_from(format!(
            "/v1/{}",
            std::str::from_utf8(enclave).expect("valid utf8")
        ))
        .unwrap()
    }
}

impl EnclaveKind for Tpm2Snp {
    type RaftConfigType = &'static RaftConfig;
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

impl PpssSetup for Svr3Env<'_> {
    type ConnectionResults = (
        Result<SvrConnection<Sgx>, Error>,
        Result<SvrConnection<Nitro>, Error>,
        Result<SvrConnection<Tpm2Snp>, Error>,
    );
    type ServerIds = [u64; 3];

    fn server_ids() -> Self::ServerIds {
        [1, 2, 3]
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

impl<E: EnclaveKind + NewHandshake, C: ConnectionManager> EnclaveEndpointConnection<E, C> {
    pub(crate) async fn connect<S: AsyncDuplexStream, T: TransportConnector<Stream = S>>(
        &self,
        auth: Auth,
        transport_connector: T,
        log_tag: Arc<str>,
    ) -> Result<(AttestedConnection, ServiceConnectionInfo), Error>
    where
        C: ConnectionManager,
    {
        // Delegate to a function that dynamically-dispatches. This could be
        // inlined, but then the body would be duplicated in the generated code
        // for each instantiation of this trait (of which there is one per
        // unique `E: EnclaveKind`).
        connect_attested(
            &self.endpoint_connection,
            auth,
            transport_connector,
            log_tag,
            &move |attestation_message| E::new_handshake(&self.params, attestation_message),
        )
        .await
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

/// Create an `AttestedConnection`.
///
/// Making the handshaker a concrete type (via `&dyn`) prevents this from being
/// instantiated multiple times and duplicated in the generated code.
async fn connect_attested<C: ConnectionManager, T: TransportConnector>(
    endpoint_connection: &EndpointConnection<C>,
    auth: Auth,
    transport_connector: T,
    log_tag: Arc<str>,
    do_handshake: &(dyn Sync + Fn(&[u8]) -> enclave::Result<enclave::Handshake>),
) -> Result<(AttestedConnection, ServiceConnectionInfo), Error> {
    let connector = WebSocketStreamConnector::new(
        transport_connector,
        WebSocketRouteFragment {
            ws_config: endpoint_connection.config.ws_config,
            endpoint: endpoint_connection.config.endpoint.clone(),
            headers: HeaderMap::from_iter([auth.as_header()]),
        },
        endpoint_connection.config.max_connection_time,
    );
    let connector = WebSocketServiceConnector::new(connector);
    let service_initializer = ServiceInitializer::new(connector, &endpoint_connection.manager);
    let connection_attempt_result = service_initializer.connect().await;
    let (websocket, connection_info) = match connection_attempt_result {
        ServiceState::Active(websocket, _) => Ok(websocket),
        ServiceState::Error(e) => Err(Error::WebSocketConnect(e)),
        ServiceState::Cooldown(_) | ServiceState::ConnectionTimedOut => {
            Err(Error::ConnectionTimedOut)
        }
        ServiceState::Inactive => {
            unreachable!("can't be returned by the initializer")
        }
    }?;
    let attested = AttestedConnection::connect(
        websocket,
        endpoint_connection.config.ws2_config(),
        log_tag,
        do_handshake,
    )
    .await?;
    Ok((attested, connection_info))
}

impl<E: EnclaveKind> EnclaveEndpointConnection<E, SingleRouteThrottlingConnectionManager> {
    pub fn new(
        endpoint: &EnclaveEndpoint<'static, E>,
        connect_timeout: Duration,
        network_change_event: &ObservableEvent,
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
        network_change_event: &ObservableEvent,
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

impl NewHandshake for Sgx {
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
            enclave::HandshakeType::PostQuantum,
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
            params
                .raft_config
                .as_raft_config()
                .expect("Raft config must be present for Nitro"),
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
            params
                .raft_config
                .as_raft_config()
                .expect("Raft config must be present for Tpm2Snp"),
        )
    }
}

#[cfg(test)]
mod test {
    use std::fmt::Debug;
    use std::sync::Arc;

    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use libsignal_net_infra::connection_manager::ConnectionAttemptOutcome;
    use libsignal_net_infra::errors::TransportConnectError;
    use libsignal_net_infra::host::Host;
    use libsignal_net_infra::ws::WebSocketConnectError;
    use libsignal_net_infra::{
        Alpn, HttpRequestDecoratorSeq, RouteType, StreamAndInfo, TransportConnectionParams,
    };
    use nonzero_ext::nonzero;
    use tokio::net::TcpStream;
    use tokio_boring_signal::SslStream;

    use super::*;
    use crate::auth::Auth;

    #[derive(Clone, Debug)]
    struct AlwaysFailingConnector;

    #[async_trait]
    impl TransportConnector for AlwaysFailingConnector {
        type Stream = SslStream<TcpStream>;

        async fn connect(
            &self,
            _connection_params: &TransportConnectionParams,
            _alpn: Alpn,
        ) -> Result<StreamAndInfo<Self::Stream>, TransportConnectError> {
            Err(TransportConnectError::TcpConnectionFailed)
        }
    }

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    async fn enclave_connect<C: ConnectionManager>(
        manager: C,
    ) -> Result<AttestedConnection, Error> {
        let mr_enclave = MrEnclave::new(b"abcdef".as_slice());
        let connection = EnclaveEndpointConnection {
            endpoint_connection: EndpointConnection {
                manager,
                config: make_ws_config(PathAndQuery::from_static("/endpoint"), CONNECT_TIMEOUT),
            },
            params: EndpointParams::<Cdsi> {
                mr_enclave,
                raft_config: (),
            },
        };

        connection
            .connect(
                Auth {
                    password: "asdf".to_string(),
                    username: "fdsa".to_string(),
                },
                AlwaysFailingConnector,
                "test".into(),
            )
            .await
            .map(|(connection, _info)| connection)
    }

    fn fake_connection_params() -> ConnectionParams {
        ConnectionParams {
            route_type: RouteType::Direct,
            transport: TransportConnectionParams {
                sni: Arc::from("fake-sni"),
                tcp_host: Host::Domain("fake".into()),
                port: nonzero!(1234u16),
                certs: libsignal_net_infra::certs::RootCertificates::Native,
            },
            http_request_decorator: HttpRequestDecoratorSeq::default(),
            http_host: Arc::from("fake-http"),
            connection_confirmation_header: None,
        }
    }

    #[tokio::test]
    async fn single_route_enclave_connect_failure() {
        let result = enclave_connect(SingleRouteThrottlingConnectionManager::new(
            fake_connection_params(),
            CONNECT_TIMEOUT,
            &ObservableEvent::default(),
        ))
        .await;
        assert_matches!(
            result,
            Err(Error::WebSocketConnect(
                WebSocketServiceConnectError::Connect(
                    WebSocketConnectError::Transport(TransportConnectError::TcpConnectionFailed),
                    _
                )
            ))
        );
    }

    #[tokio::test]
    async fn multi_route_enclave_connect_failure() {
        let result = enclave_connect(MultiRouteConnectionManager::new(vec![
            SingleRouteThrottlingConnectionManager::new(
                fake_connection_params(),
                CONNECT_TIMEOUT,
                &ObservableEvent::default(),
            );
            3
        ]))
        .await;
        assert_matches!(result, Err(Error::ConnectionTimedOut));
    }

    /// Demonstrate a scenario where an enclave connection can be attempted
    /// where the service can produce [`ServiceState::Cooldown`].
    #[tokio::test]
    async fn multi_route_enclave_connect_cooldown() {
        let connection_manager = MultiRouteConnectionManager::new(vec![
            SingleRouteThrottlingConnectionManager::new(
                fake_connection_params(),
                CONNECT_TIMEOUT,
                &ObservableEvent::default(),
            );
            3
        ]);

        // Repeatedly try connecting unsuccessfully until all the inner routes
        // are throttling, with a max count to prevent infinite looping.
        let mut limit_max_tries = 0..100;
        loop {
            let _ = limit_max_tries
                .next()
                .expect("didn't finish setup after many iterations");
            match connection_manager
                .connect_or_wait(|_conn_params| {
                    std::future::ready(Err::<(), _>(WebSocketServiceConnectError::timeout()))
                })
                .await
            {
                ConnectionAttemptOutcome::WaitUntil(_) => break,
                ConnectionAttemptOutcome::Attempted(_) => (),
                ConnectionAttemptOutcome::TimedOut => (),
            }
        }

        let result = enclave_connect(connection_manager).await;
        assert_matches!(result, Err(Error::ConnectionTimedOut));
    }
}
