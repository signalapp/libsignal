//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;
use std::time::Duration;

use attest::svr2::RaftConfig;
use derive_where::derive_where;
use http::uri::PathAndQuery;

use crate::env::{Svr3Env, WS_KEEP_ALIVE_INTERVAL, WS_MAX_IDLE_TIME};
use crate::infra::certs::RootCertificates;
use crate::infra::connection_manager::{
    MultiRouteConnectionManager, SingleRouteThrottlingConnectionManager,
};
use crate::infra::ws::{AttestedConnection, WebSocketClientConnector, WebSocketConfig};
use crate::infra::{ConnectionParams, TransportConnector};
use crate::svr::SvrConnection;

pub trait EnclaveKind {
    fn url_path(enclave: &[u8]) -> PathAndQuery;
}
pub trait Svr3Flavor: EnclaveKind {
    const SERVER_ID: u64;
}
pub enum Cdsi {}

pub enum Sgx {}

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
impl Svr3Flavor for Sgx {
    const SERVER_ID: u64 = 0;
}

pub trait HasConnections {
    type Connections<'a>: ArrayIsh<&'a mut AttestedConnection>
    where
        Self: 'a;
    fn get_connections(&mut self) -> Self::Connections<'_>;
}

impl<A> HasConnections for A
where
    A: AsMut<AttestedConnection>,
{
    type Connections<'a> = [&'a mut AttestedConnection; 1] where Self: 'a;
    fn get_connections(&mut self) -> Self::Connections<'_> {
        [self.as_mut()]
    }
}

impl<A, B> HasConnections for (A, B)
where
    A: AsMut<AttestedConnection>,
    B: AsMut<AttestedConnection>,
{
    type Connections<'a> = [&'a mut AttestedConnection; 2] where Self: 'a;
    fn get_connections(&mut self) -> Self::Connections<'_> {
        [self.0.as_mut(), self.1.as_mut()]
    }
}

impl<A, B, C> HasConnections for (A, B, C)
where
    A: AsMut<AttestedConnection>,
    B: AsMut<AttestedConnection>,
    C: AsMut<AttestedConnection>,
{
    type Connections<'a> =[&'a mut AttestedConnection; 3] where Self: 'a;
    fn get_connections(&mut self) -> Self::Connections<'_> {
        [self.0.as_mut(), self.1.as_mut(), self.2.as_mut()]
    }
}

pub trait ArrayIsh<T>: AsMut<[T]> {
    const N: usize;
}

impl<T, const N: usize> ArrayIsh<T> for [T; N] {
    const N: usize = N;
}

pub trait PpssSetup {
    type Connections: HasConnections;
    type ServerIds: ArrayIsh<u64>;
    const N: usize = Self::ServerIds::N;
    fn server_ids() -> Self::ServerIds;
}

impl PpssSetup for Svr3Env<'_> {
    type Connections = SvrConnection<Sgx>;
    type ServerIds = [u64; 1];

    fn server_ids() -> Self::ServerIds {
        [Sgx::SERVER_ID]
    }
}

#[derive_where(Clone, Copy; Bytes)]
pub struct MrEnclave<Bytes, S> {
    inner: Bytes,
    service_kind: PhantomData<S>,
}

impl<Bytes, S: EnclaveKind> MrEnclave<Bytes, S> {
    pub const fn new(bytes: Bytes) -> Self {
        Self {
            inner: bytes,
            service_kind: PhantomData,
        }
    }
}

impl<Bytes: AsRef<[u8]>, S> AsRef<[u8]> for MrEnclave<Bytes, S> {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

#[derive_where(Copy, Clone)]
pub struct EnclaveEndpoint<'a, S: EnclaveKind> {
    pub host: &'a str,
    pub mr_enclave: MrEnclave<&'a [u8], S>,
}

impl<S: EnclaveKind> EnclaveEndpoint<'_, S> {
    pub fn direct_connection(&self) -> ConnectionParams {
        ConnectionParams::direct_to_host(self.host)
    }
}

pub struct EndpointConnection<S: EnclaveKind, C, T> {
    pub(crate) mr_enclave: MrEnclave<&'static [u8], S>,
    pub(crate) connection_manager: C,
    pub(crate) connector: WebSocketClientConnector<T>,
    pub(crate) raft_config_override: Option<&'static RaftConfig>,
}

impl<S: EnclaveKind, T: TransportConnector>
    EndpointConnection<S, SingleRouteThrottlingConnectionManager, T>
{
    pub fn new(
        endpoint: EnclaveEndpoint<'static, S>,
        connect_timeout: Duration,
        transport_connector: T,
    ) -> Self {
        Self::with_custom_properties(
            endpoint,
            connect_timeout,
            transport_connector,
            RootCertificates::Signal,
            None,
        )
    }

    pub fn with_custom_properties(
        endpoint: EnclaveEndpoint<'static, S>,
        connect_timeout: Duration,
        transport_connector: T,
        certs: RootCertificates,
        raft_config_override: Option<&'static RaftConfig>,
    ) -> Self {
        Self {
            connection_manager: SingleRouteThrottlingConnectionManager::new(
                endpoint.direct_connection().with_certs(certs),
                connect_timeout,
            ),
            connector: WebSocketClientConnector::new(
                transport_connector,
                make_ws_config(&endpoint.mr_enclave, connect_timeout),
            ),
            mr_enclave: endpoint.mr_enclave,
            raft_config_override,
        }
    }
}

impl<S: EnclaveKind, T: TransportConnector> EndpointConnection<S, MultiRouteConnectionManager, T> {
    pub fn new_multi(
        mr_enclave: MrEnclave<&'static [u8], S>,
        connection_params: impl IntoIterator<Item = ConnectionParams>,
        connect_timeout: Duration,
        transport_connector: T,
    ) -> Self {
        Self {
            connection_manager: MultiRouteConnectionManager::new(
                connection_params
                    .into_iter()
                    .map(|params| {
                        SingleRouteThrottlingConnectionManager::new(params, connect_timeout)
                    })
                    .collect(),
                connect_timeout,
            ),
            connector: WebSocketClientConnector::new(
                transport_connector,
                make_ws_config(&mr_enclave, connect_timeout),
            ),
            mr_enclave,
            raft_config_override: None,
        }
    }
}

fn make_ws_config<S: EnclaveKind>(
    mr_enclave: &MrEnclave<&'static [u8], S>,
    connect_timeout: Duration,
) -> WebSocketConfig {
    WebSocketConfig {
        ws_config: tungstenite::protocol::WebSocketConfig::default(),
        endpoint: S::url_path(mr_enclave.as_ref()),
        max_connection_time: connect_timeout,
        keep_alive_interval: WS_KEEP_ALIVE_INTERVAL,
        max_idle_time: WS_MAX_IDLE_TIME,
    }
}
