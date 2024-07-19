//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::*;

use aes_gcm_siv::aead::rand_core::CryptoRngCore;
use async_trait::async_trait;
use futures_util::future::join3;
use http::uri::PathAndQuery;

use libsignal_net::auth::Auth;
use libsignal_net::enclave::{
    Cdsi, EnclaveEndpoint, EnclaveEndpointConnection, EnclaveKind, Nitro, PpssSetup, Sgx, Tpm2Snp,
};
use libsignal_net::env::{add_user_agent_header, Env, Svr3Env};
use libsignal_net::infra::connection_manager::MultiRouteConnectionManager;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::tcp_ssl::{
    DirectConnector as TcpSslDirectConnector, ProxyConnector as TcpSslProxyConnector,
    TcpSslConnector, TcpSslConnectorStream,
};
use libsignal_net::infra::{make_ws_config, EndpointConnection};
use libsignal_net::svr::SvrConnection;
use libsignal_net::svr3::traits::*;
use libsignal_net::svr3::{Error, OpaqueMaskedShareSet};
use libsignal_net::timeouts::ONE_ROUTE_CONNECTION_TIMEOUT;
use libsignal_net::utils::ObservableEvent;
use libsignal_svr3::EvaluationResult;
use std::marker::PhantomData;
use std::num::{NonZeroU16, NonZeroU32};
use std::panic::RefUnwindSafe;

pub mod cdsi;
pub mod chat;
pub mod tokio;

pub use tokio::TokioAsyncContext;

#[derive(num_enum::TryFromPrimitive)]
#[repr(u8)]
#[derive(Clone, Copy, strum::Display)]
pub enum Environment {
    Staging = 0,
    Prod = 1,
}

impl Environment {
    fn env<'a>(self) -> Env<'a, Svr3Env<'a>> {
        match self {
            Self::Staging => libsignal_net::env::STAGING,
            Self::Prod => libsignal_net::env::PROD,
        }
    }
}

pub struct ConnectionManager {
    chat: EndpointConnection<MultiRouteConnectionManager>,
    cdsi: EnclaveEndpointConnection<Cdsi, MultiRouteConnectionManager>,
    svr3: (
        EnclaveEndpointConnection<Sgx, MultiRouteConnectionManager>,
        EnclaveEndpointConnection<Nitro, MultiRouteConnectionManager>,
        EnclaveEndpointConnection<Tpm2Snp, MultiRouteConnectionManager>,
    ),
    transport_connector: std::sync::Mutex<TcpSslConnector>,
    network_change_event: ObservableEvent,
}

impl RefUnwindSafe for ConnectionManager {}

impl ConnectionManager {
    pub fn new(environment: Environment, user_agent: String) -> Self {
        log::info!("Initializing connection manager for {}...", &environment);
        let network_change_event = ObservableEvent::new();
        let dns_resolver = DnsResolver::new_with_static_fallback(
            environment.env().static_fallback(),
            &network_change_event,
        );
        let transport_connector =
            std::sync::Mutex::new(TcpSslDirectConnector::new(dns_resolver).into());
        let chat_endpoint =
            PathAndQuery::from_static(libsignal_net::env::constants::WEB_SOCKET_PATH);
        let chat_connection_params = environment
            .env()
            .chat_domain_config
            .connection_params_with_fallback();
        let chat_connection_params = add_user_agent_header(chat_connection_params, &user_agent);
        let chat_ws_config = make_ws_config(chat_endpoint, ONE_ROUTE_CONNECTION_TIMEOUT);
        Self {
            chat: EndpointConnection::new_multi(
                chat_connection_params,
                ONE_ROUTE_CONNECTION_TIMEOUT,
                chat_ws_config,
            ),
            cdsi: Self::endpoint_connection(&environment.env().cdsi, &user_agent),
            svr3: (
                Self::endpoint_connection(environment.env().svr3.sgx(), &user_agent),
                Self::endpoint_connection(environment.env().svr3.nitro(), &user_agent),
                Self::endpoint_connection(environment.env().svr3.tpm2snp(), &user_agent),
            ),
            transport_connector,
            network_change_event,
        }
    }

    pub fn set_proxy(&self, host: &str, port: Option<NonZeroU16>) -> Result<(), std::io::Error> {
        let mut guard = self.transport_connector.lock().expect("not poisoned");
        // We take port as an i32 because Java 'short' is signed and thus can't represent all port
        // numbers, and we want too-large port numbers to be handled the same way as 0.
        match port {
            Some(port) => {
                let proxy_addr = (host, port);
                match &mut *guard {
                    TcpSslConnector::Direct(direct) => {
                        *guard = direct.with_proxy(proxy_addr).into()
                    }
                    TcpSslConnector::Proxied(proxied) => proxied.set_proxy(proxy_addr),
                    TcpSslConnector::Invalid(dns_resolver) => {
                        *guard = TcpSslProxyConnector::new(dns_resolver.clone(), proxy_addr).into()
                    }
                };
                Ok(())
            }
            None => {
                match &*guard {
                    TcpSslConnector::Direct(TcpSslDirectConnector { dns_resolver, .. })
                    | TcpSslConnector::Proxied(TcpSslProxyConnector { dns_resolver, .. }) => {
                        *guard = TcpSslConnector::Invalid(dns_resolver.clone())
                    }
                    TcpSslConnector::Invalid(_dns_resolver) => (),
                }
                Err(std::io::ErrorKind::InvalidInput.into())
            }
        }
    }

    pub fn clear_proxy(&self) {
        let mut guard = self.transport_connector.lock().expect("not poisoned");
        match &*guard {
            TcpSslConnector::Direct(_direct) => (),
            TcpSslConnector::Proxied(TcpSslProxyConnector { dns_resolver, .. })
            | TcpSslConnector::Invalid(dns_resolver) => {
                *guard = TcpSslDirectConnector::new(dns_resolver.clone()).into()
            }
        };
    }

    pub fn set_ipv6_enabled(&self, ipv6_enabled: bool) {
        let mut guard = self.transport_connector.lock().expect("not poisoned");
        guard.set_ipv6_enabled(ipv6_enabled);
    }

    fn endpoint_connection<E: EnclaveKind>(
        endpoint: &EnclaveEndpoint<'static, E>,
        user_agent: &str,
    ) -> EnclaveEndpointConnection<E, MultiRouteConnectionManager> {
        let params = endpoint.domain_config.connection_params_with_fallback();
        let params = add_user_agent_header(params, user_agent);
        EnclaveEndpointConnection::new_multi(endpoint, params, ONE_ROUTE_CONNECTION_TIMEOUT)
    }

    pub fn network_changed(&self) {
        self.network_change_event.fire()
    }
}

bridge_as_handle!(ConnectionManager);

pub enum PreviousVersion {}
pub enum CurrentVersion {}

pub struct Svr3Client<'a, Kind> {
    connection_manager: &'a ConnectionManager,
    auth: Auth,
    kind: PhantomData<Kind>,
}

impl<'a, Kind> Svr3Client<'a, Kind> {
    fn new(connection_manager: &'a ConnectionManager, auth: Auth) -> Self {
        Self {
            connection_manager,
            auth,
            kind: PhantomData,
        }
    }
}

pub struct Svr3Clients<'a> {
    pub previous: Svr3Client<'a, PreviousVersion>,
    pub current: Svr3Client<'a, CurrentVersion>,
}

impl<'a> Svr3Clients<'a> {
    pub fn new(
        connection_manager: &'a ConnectionManager,
        username: String,
        password: String,
    ) -> Self {
        let auth = Auth { username, password };
        Self {
            previous: Svr3Client::new(connection_manager, auth.clone()),
            current: Svr3Client::new(connection_manager, auth),
        }
    }
}

#[async_trait]
impl<'a> Svr3Connect for Svr3Client<'a, CurrentVersion> {
    type Stream = TcpSslConnectorStream;
    type Env = Svr3Env<'static>;

    async fn connect(&self) -> <Self::Env as PpssSetup<Self::Stream>>::ConnectionResults {
        let ConnectionManager {
            svr3: (sgx, nitro, tpm2snp),
            transport_connector,
            ..
        } = &self.connection_manager;
        let transport_connector = transport_connector.lock().expect("not poisoned").clone();
        let (sgx, nitro, tpm2snp) = join3(
            SvrConnection::connect(self.auth.clone(), sgx, transport_connector.clone()),
            SvrConnection::connect(self.auth.clone(), nitro, transport_connector.clone()),
            SvrConnection::connect(self.auth.clone(), tpm2snp, transport_connector),
        )
        .await;
        (sgx, nitro, tpm2snp)
    }
}

#[async_trait]
impl<'a> Backup for Svr3Client<'a, PreviousVersion> {
    async fn backup(
        &self,
        _password: &str,
        _secret: [u8; 32],
        _max_tries: NonZeroU32,
        _rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<OpaqueMaskedShareSet, Error> {
        empty_env::backup().await
    }
}

#[async_trait]
impl<'a> Restore for Svr3Client<'a, PreviousVersion> {
    async fn restore(
        &self,
        _password: &str,
        _share_set: OpaqueMaskedShareSet,
        _rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<EvaluationResult, Error> {
        empty_env::restore().await
    }
}

#[async_trait]
impl<'a> Remove for Svr3Client<'a, PreviousVersion> {
    async fn remove(&self) -> Result<(), Error> {
        empty_env::remove().await
    }
}

#[async_trait]
impl<'a> Query for Svr3Client<'a, PreviousVersion> {
    async fn query(&self) -> Result<u32, Error> {
        empty_env::query().await
    }
}

// These functions define the behavior of the empty `PreviousVersion`
// when there is no migration going on.
// When there _is_ migration both current and previous clients should instead
// implement `Svr3Connect` and use the blanket implementations of the traits.
mod empty_env {
    use super::*;

    pub async fn backup() -> Result<OpaqueMaskedShareSet, Error> {
        // Ideally it would be a panic, as this is certainly a programmer error
        // that needs to be fixed. However, panics are propagated to the clients
        // and become runtime exceptions that can be caught. This way we will
        // don't change the set of expected errors on the client side, and get a
        // descriptive message in the logs.
        Err(Error::AttestationError(
            attest::enclave::Error::AttestationDataError {
                reason: "This SVR3 environment does not exist".to_string(),
            },
        ))
    }

    pub async fn restore() -> Result<EvaluationResult, Error> {
        // This is the only error value that will make `restore_with_fallback`
        // function effectively ignore this SVR3 setup, thus making it possible
        // to use `restore_with_fallback` for all restores unconditionally.
        Err(Error::DataMissing)
    }

    pub async fn remove() -> Result<(), Error> {
        Ok(())
    }

    pub async fn query() -> Result<u32, Error> {
        Err(Error::DataMissing)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use test_case::test_case;

    #[test_case(Environment::Staging; "staging")]
    #[test_case(Environment::Prod; "prod")]
    fn can_create_connection_manager(env: Environment) {
        let _ = ConnectionManager::new(env, "test-user-agent".to_string());
    }
}
