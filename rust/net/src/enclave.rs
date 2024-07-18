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

pub enum Sgx {}

pub enum Nitro {}

pub enum Tpm2Snp {}

impl EnclaveKind for Cdsi {
    type RaftConfigType = ();
    fn url_path(enclave: &[u8]) -> PathAndQuery {
        PathAndQuery::try_from(format!("/v1/{}/discovery", hex::encode(enclave))).unwrap()
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

pub trait IntoConnectionResults {
    type Stream;
    type ConnectionResults: ArrayIsh<Result<AttestedConnection<Self::Stream>, Error>> + Send;
    fn into_connection_results(self) -> Self::ConnectionResults;
}

pub trait IntoAttestedConnection: Into<AttestedConnection<Self::Stream>> {
    type Stream: Send;
}

impl<S: Send> IntoAttestedConnection for AttestedConnection<S> {
    type Stream = S;
}

impl<A> IntoConnectionResults for Result<A, Error>
where
    A: IntoAttestedConnection,
{
    type Stream = A::Stream;
    type ConnectionResults = [Result<AttestedConnection<Self::Stream>, Error>; 1];
    fn into_connection_results(self) -> Self::ConnectionResults {
        [self.map(Into::into)]
    }
}

impl<A, B> IntoConnectionResults for (Result<A, Error>, Result<B, Error>)
where
    A: IntoAttestedConnection,
    B: IntoAttestedConnection<Stream = A::Stream>,
{
    type Stream = A::Stream;
    type ConnectionResults = [Result<AttestedConnection<Self::Stream>, Error>; 2];
    fn into_connection_results(self) -> Self::ConnectionResults {
        [self.0.map(Into::into), self.1.map(Into::into)]
    }
}

impl<A, B, C> IntoConnectionResults for (Result<A, Error>, Result<B, Error>, Result<C, Error>)
where
    A: IntoAttestedConnection,
    B: IntoAttestedConnection<Stream = A::Stream>,
    C: IntoAttestedConnection<Stream = A::Stream>,
{
    type Stream = A::Stream;
    type ConnectionResults = [Result<AttestedConnection<Self::Stream>, Error>; 3];
    fn into_connection_results(self) -> Self::ConnectionResults {
        [
            self.0.map(Into::into),
            self.1.map(Into::into),
            self.2.map(Into::into),
        ]
    }
}

pub trait ArrayIsh<T>: AsRef<[T]> + IntoIterator<Item = T> {
    const N: usize;
}

impl<T, const N: usize> ArrayIsh<T> for [T; N] {
    const N: usize = N;
}

pub trait PpssSetup<S> {
    type Stream;
    type ConnectionResults: IntoConnectionResults<Stream = S> + Send;
    type ServerIds: ArrayIsh<u64> + Send;
    const N: usize = Self::ServerIds::N;
    fn server_ids() -> Self::ServerIds;
}

impl<S: Send> PpssSetup<S> for Svr3Env<'_> {
    type Stream = S;
    type ConnectionResults = (
        Result<SvrConnection<Sgx, S>, Error>,
        Result<SvrConnection<Nitro, S>, Error>,
        Result<SvrConnection<Tpm2Snp, S>, Error>,
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

pub trait NewHandshake {
    fn new_handshake(
        params: &EndpointParams<Self>,
        attestation_message: &[u8],
    ) -> enclave::Result<enclave::Handshake>
    where
        Self: EnclaveKind + Sized;
}

pub struct EnclaveEndpointConnection<E: EnclaveKind, C> {
    pub(crate) endpoint_connection: EndpointConnection<C>,
    pub(crate) params: EndpointParams<'static, E>,
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
            AttestedConnectionError::Attestation(err) => Self::AttestationError(err),
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
        // Delegate to a function that dynamically-dispatches. This could be
        // inlined, but then the body would be duplicated in the generated code
        // for each instantiation of this trait (of which there is one per
        // unique `E: EnclaveKind`).
        connect_attested(
            &self.endpoint_connection,
            auth,
            transport_connector,
            &move |attestation_message| E::new_handshake(&self.params, attestation_message),
        )
        .await
    }
}

/// Create an `AttestedConnection`.
///
/// Making the handshaker a concrete type (via `&dyn`) prevents this from being
/// instantiated multiple times and duplicated in the generated code.
async fn connect_attested<
    C: ConnectionManager,
    T: TransportConnector<Stream = S>,
    S: AsyncDuplexStream,
>(
    endpoint_connection: &EndpointConnection<C>,
    auth: impl HttpBasicAuth,
    transport_connector: T,
    do_handshake: &(dyn Sync + Fn(&[u8]) -> enclave::Result<enclave::Handshake>),
) -> Result<AttestedConnection<S>, Error> {
    let auth_decorator = auth.into();
    let connector = ServiceConnectorWithDecorator::new(
        WebSocketClientConnector::<_, WebSocketServiceError>::new(
            transport_connector,
            endpoint_connection.config.clone(),
        ),
        auth_decorator,
    );
    let service_initializer = ServiceInitializer::new(connector, &endpoint_connection.manager);
    let connection_attempt_result = service_initializer.connect().await;
    let websocket = match connection_attempt_result {
        ServiceState::Active(websocket, _) => Ok(websocket),
        ServiceState::Error(e) => Err(Error::WebSocketConnect(e)),
        ServiceState::Cooldown(_) | ServiceState::ConnectionTimedOut => {
            Err(Error::ConnectionTimedOut)
        }
        ServiceState::Inactive => {
            unreachable!("can't be returned by the initializer")
        }
    }?;
    let attested = AttestedConnection::connect(websocket, do_handshake).await?;
    Ok(attested)
}

impl<E: EnclaveKind> EnclaveEndpointConnection<E, SingleRouteThrottlingConnectionManager> {
    pub fn new(endpoint: &EnclaveEndpoint<'static, E>, connect_timeout: Duration) -> Self {
        Self {
            endpoint_connection: EndpointConnection {
                manager: SingleRouteThrottlingConnectionManager::new(
                    endpoint.domain_config.connection_params(),
                    connect_timeout,
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
    ) -> Self {
        Self {
            endpoint_connection: EndpointConnection::new_multi(
                connection_params,
                one_route_connect_timeout,
                make_ws_config(
                    E::url_path(endpoint.params.mr_enclave.as_ref()),
                    one_route_connect_timeout,
                ),
            ),
            params: endpoint.params.clone(),
        }
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

    use assert_matches::assert_matches;
    use async_trait::async_trait;
    use nonzero_ext::nonzero;
    use tokio::net::TcpStream;
    use tokio_boring::SslStream;

    use crate::auth::Auth;
    use crate::infra::connection_manager::ConnectionAttemptOutcome;
    use crate::infra::errors::TransportConnectError;
    use crate::infra::{Alpn, HttpRequestDecoratorSeq, RouteType, StreamAndInfo};

    use super::*;

    #[derive(Clone, Debug)]
    struct AlwaysFailingConnector;

    #[async_trait]
    impl TransportConnector for AlwaysFailingConnector {
        type Stream = SslStream<TcpStream>;

        async fn connect(
            &self,
            _connection_params: &ConnectionParams,
            _alpn: Alpn,
        ) -> Result<StreamAndInfo<Self::Stream>, TransportConnectError> {
            Err(TransportConnectError::TcpConnectionFailed)
        }
    }

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    async fn enclave_connect<C: ConnectionManager>(
        manager: C,
    ) -> Result<AttestedConnection<SslStream<TcpStream>>, Error> {
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
            )
            .await
    }

    fn fake_connection_params() -> ConnectionParams {
        ConnectionParams::new(
            RouteType::Direct,
            "fake",
            "fake-sni",
            nonzero!(1234u16),
            HttpRequestDecoratorSeq::default(),
            crate::infra::certs::RootCertificates::Native,
        )
    }

    #[tokio::test]
    async fn single_route_enclave_connect_failure() {
        let result = enclave_connect(SingleRouteThrottlingConnectionManager::new(
            fake_connection_params(),
            CONNECT_TIMEOUT,
        ))
        .await;
        assert_matches!(
            result,
            Err(Error::WebSocketConnect(WebSocketConnectError::Transport(
                TransportConnectError::TcpConnectionFailed
            )))
        );
    }

    #[tokio::test]
    async fn multi_route_enclave_connect_failure() {
        let result = enclave_connect(MultiRouteConnectionManager::new(vec![
            SingleRouteThrottlingConnectionManager::new(
                fake_connection_params(),
                CONNECT_TIMEOUT,
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
                    std::future::ready(Err::<(), _>(WebSocketConnectError::Timeout))
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
