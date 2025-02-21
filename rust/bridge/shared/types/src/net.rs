//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::panic::RefUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aes_gcm_siv::aead::rand_core::CryptoRngCore;
use async_trait::async_trait;
use futures_util::future::join3;
use http::HeaderName;
use libsignal_net::auth::Auth;
use libsignal_net::connect_state::{ConnectState, SUGGESTED_CONNECT_CONFIG};
use libsignal_net::enclave::{
    Cdsi, EnclaveEndpoint, EnclaveEndpointConnection, EnclaveKind, NewHandshake, Nitro, PpssSetup,
    Sgx, Svr3Flavor, Tpm2Snp,
};
use libsignal_net::env::{add_user_agent_header, Env, Svr3Env, UserAgent};
use libsignal_net::infra::connection_manager::MultiRouteConnectionManager;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::route::{
    ConnectionProxyConfig, DirectOrProxyProvider, RouteProviderExt as _,
};
use libsignal_net::infra::tcp_ssl::{InvalidProxyConfig, TcpSslConnector};
use libsignal_net::infra::timeouts::ONE_ROUTE_CONNECTION_TIMEOUT;
use libsignal_net::infra::utils::ObservableEvent;
use libsignal_net::infra::{AsHttpHeader as _, EnableDomainFronting, EndpointConnection};
use libsignal_net::svr::SvrConnection;
use libsignal_net::svr3::traits::*;
use libsignal_net::svr3::{Error, OpaqueMaskedShareSet};
use libsignal_net::ws::WebSocketServiceConnectError;
use libsignal_svr3::EvaluationResult;

use crate::*;

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
    pub fn env<'a>(self) -> Env<'a, Svr3Env<'a>> {
        match self {
            Self::Staging => libsignal_net::env::STAGING,
            Self::Prod => libsignal_net::env::PROD,
        }
    }
}

type Svr3EndpointConnections = (
    EnclaveEndpointConnection<Sgx, MultiRouteConnectionManager>,
    EnclaveEndpointConnection<Nitro, MultiRouteConnectionManager>,
    EnclaveEndpointConnection<Tpm2Snp, MultiRouteConnectionManager>,
);

struct EndpointConnections {
    chat: EndpointConnection<MultiRouteConnectionManager>,
    cdsi: EnclaveEndpointConnection<Cdsi, MultiRouteConnectionManager>,
    svr3: Svr3EndpointConnections,
    enable_fronting: EnableDomainFronting,
}

impl EndpointConnections {
    fn new(
        env: &Env<'static, Svr3Env<'static>>,
        user_agent: &UserAgent,
        use_fallbacks: bool,
        network_change_event: &ObservableEvent,
    ) -> Self {
        log::info!(
            "Creating endpoint connections (fallbacks {}) for {} and others",
            if use_fallbacks { "enabled" } else { "disabled" },
            // Note: this is *not* using log_safe_domain, because it is always the direct route.
            // Either it's chat.signal.org, chat.staging.signal.org, or something that indicates
            // testing. (Or the person running this isn't Signal.)
            env.chat_domain_config.connect.hostname
        );
        let chat = libsignal_net::chat::endpoint_connection(
            &env.chat_domain_config.connect,
            user_agent,
            use_fallbacks,
            network_change_event,
        );
        let cdsi =
            Self::endpoint_connection(&env.cdsi, user_agent, use_fallbacks, network_change_event);
        let svr3 = (
            Self::endpoint_connection(
                env.svr3.sgx(),
                user_agent,
                use_fallbacks,
                network_change_event,
            ),
            Self::endpoint_connection(
                env.svr3.nitro(),
                user_agent,
                use_fallbacks,
                network_change_event,
            ),
            Self::endpoint_connection(
                env.svr3.tpm2snp(),
                user_agent,
                use_fallbacks,
                network_change_event,
            ),
        );
        Self {
            chat,
            cdsi,
            svr3,
            enable_fronting: EnableDomainFronting(use_fallbacks),
        }
    }

    fn endpoint_connection<E: EnclaveKind>(
        endpoint: &EnclaveEndpoint<'static, E>,
        user_agent: &UserAgent,
        include_fallback: bool,
        network_change_event: &ObservableEvent,
    ) -> EnclaveEndpointConnection<E, MultiRouteConnectionManager> {
        let params = if include_fallback {
            endpoint
                .domain_config
                .connect
                .connection_params_with_fallback()
        } else {
            vec![endpoint.domain_config.connect.direct_connection_params()]
        };
        let params = add_user_agent_header(params, user_agent);
        EnclaveEndpointConnection::new_multi(
            endpoint,
            params,
            ONE_ROUTE_CONNECTION_TIMEOUT,
            network_change_event,
        )
    }
}

pub struct ConnectionManager {
    env: Env<'static, Svr3Env<'static>>,
    user_agent: UserAgent,
    dns_resolver: DnsResolver,
    connect: ::tokio::sync::RwLock<ConnectState>,
    // We could split this up to a separate mutex on each kind of connection,
    // but we don't hold it for very long anyway (just enough to clone the Arc).
    endpoints: std::sync::Mutex<Arc<EndpointConnections>>,
    transport_connector: std::sync::Mutex<TcpSslConnector>,
    most_recent_network_change: std::sync::Mutex<Instant>,
    network_change_event: ObservableEvent,
}

impl RefUnwindSafe for ConnectionManager {}

impl ConnectionManager {
    pub fn new(environment: Environment, user_agent: &str) -> Self {
        log::info!("Initializing connection manager for {}...", &environment);
        Self::new_from_static_environment(environment.env(), user_agent)
    }

    pub fn new_from_static_environment(
        env: Env<'static, Svr3Env<'static>>,
        user_agent: &str,
    ) -> Self {
        let network_change_event = ObservableEvent::new();
        let user_agent = UserAgent::with_libsignal_version(user_agent);

        let dns_resolver =
            DnsResolver::new_with_static_fallback(env.static_fallback(), &network_change_event);
        let transport_connector =
            std::sync::Mutex::new(TcpSslConnector::new_direct(dns_resolver.clone()));
        let endpoints = std::sync::Mutex::new(
            EndpointConnections::new(&env, &user_agent, false, &network_change_event).into(),
        );
        Self {
            env,
            endpoints,
            user_agent,
            connect: ConnectState::new(SUGGESTED_CONNECT_CONFIG),
            dns_resolver,
            transport_connector,
            most_recent_network_change: Instant::now().into(),
            network_change_event,
        }
    }

    pub fn set_proxy(&self, proxy: ConnectionProxyConfig) {
        let mut guard = self.transport_connector.lock().expect("not poisoned");
        guard.set_proxy(proxy);
    }

    pub fn set_invalid_proxy(&self) {
        let mut guard = self.transport_connector.lock().expect("not poisoned");
        guard.set_invalid();
    }

    pub fn clear_proxy(&self) {
        let mut guard = self.transport_connector.lock().expect("not poisoned");
        guard.clear_proxy();
    }

    pub fn is_using_proxy(&self) -> Result<bool, InvalidProxyConfig> {
        let guard = self.transport_connector.lock().expect("not poisoned");
        guard.proxy().map(|proxy| proxy.is_some())
    }

    pub fn set_ipv6_enabled(&self, ipv6_enabled: bool) {
        let mut guard = self.transport_connector.lock().expect("not poisoned");
        guard.set_ipv6_enabled(ipv6_enabled);
        self.connect.blocking_write().route_resolver.allow_ipv6 = ipv6_enabled;
    }

    /// Resets the endpoint connections to include or exclude censorship circumvention routes.
    ///
    /// This is not itself a network change event; existing working connections are expected to
    /// continue to work, and existing failing connections will continue to fail.
    pub fn set_censorship_circumvention_enabled(&self, enabled: bool) {
        let new_endpoints = EndpointConnections::new(
            &self.env,
            &self.user_agent,
            enabled,
            &self.network_change_event,
        );
        *self.endpoints.lock().expect("not poisoned") = Arc::new(new_endpoints);
    }

    const NETWORK_CHANGE_DEBOUNCE: Duration = Duration::from_secs(1);

    pub fn on_network_change(&self, now: Instant) {
        {
            let mut most_recent_change_guard = self
                .most_recent_network_change
                .lock()
                .expect("not poisoned");
            if now.saturating_duration_since(*most_recent_change_guard)
                < Self::NETWORK_CHANGE_DEBOUNCE
            {
                log::info!("ConnectionManager: on_network_change (debounced)");
                return;
            }
            *most_recent_change_guard = now;
        }
        log::info!("ConnectionManager: on_network_change");
        self.network_change_event.fire();
        self.connect.blocking_write().network_changed(now.into());
    }
}

bridge_as_handle!(ConnectionManager);
bridge_as_handle!(ConnectionProxyConfig);

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
impl Svr3Connect for Svr3Client<'_, CurrentVersion> {
    type Env = Svr3Env<'static>;

    async fn connect(&self) -> <Self::Env as PpssSetup>::ConnectionResults {
        let ConnectionManager {
            endpoints,
            transport_connector,
            connect,
            dns_resolver,
            env,
            user_agent,
            ..
        } = &self.connection_manager;
        let proxy_config: Option<libsignal_net::infra::route::ConnectionProxyConfig> =
            match (&*transport_connector.lock().expect("not poisoned")).try_into() {
                Ok(proxy_config) => proxy_config,
                Err(_) => {
                    let err = || {
                        libsignal_net::svr::Error::WebSocketConnect(
                            WebSocketServiceConnectError::invalid_proxy_configuration(),
                        )
                    };
                    return (Err(err()), Err(err()), Err(err()));
                }
            };

        let (enable_domain_fronting, sgx_ws, nitro_ws, tpm2snp_ws) = {
            let guard = endpoints.lock().expect("not poisoned");
            (
                guard.enable_fronting,
                guard.svr3.0.ws2_config(),
                guard.svr3.1.ws2_config(),
                guard.svr3.2.ws2_config(),
            )
        };
        let (sgx, nitro, tpm2snp) = (env.svr3.sgx(), env.svr3.nitro(), env.svr3.tpm2snp());

        async fn connect_one<Enclave>(
            connect_state: &::tokio::sync::RwLock<ConnectState>,
            dns_resolver: &DnsResolver,
            user_agent: &UserAgent,
            enable_domain_fronting: EnableDomainFronting,
            endpoint: &EnclaveEndpoint<'static, Enclave>,
            ws_config: libsignal_net::infra::ws2::Config,
            proxy_config: Option<&libsignal_net::infra::route::ConnectionProxyConfig>,
            auth: &Auth,
        ) -> Result<SvrConnection<Enclave>, libsignal_net::enclave::Error>
        where
            Enclave: Svr3Flavor + NewHandshake + Sized,
        {
            SvrConnection::connect(
                connect_state,
                dns_resolver,
                DirectOrProxyProvider::maybe_proxied(
                    endpoint
                        .route_provider(enable_domain_fronting)
                        .map_routes(|mut route| {
                            route.fragment.headers.extend([user_agent.as_header()]);
                            route
                        }),
                    proxy_config.cloned(),
                ),
                endpoint
                    .domain_config
                    .connect
                    .confirmation_header_name
                    .map(HeaderName::from_static),
                ws_config,
                &endpoint.params,
                auth.clone(),
            )
            .await
        }

        let (sgx, nitro, tpm2snp) = join3(
            connect_one(
                connect,
                dns_resolver,
                user_agent,
                enable_domain_fronting,
                sgx,
                sgx_ws,
                proxy_config.as_ref(),
                &self.auth,
            ),
            connect_one(
                connect,
                dns_resolver,
                user_agent,
                enable_domain_fronting,
                nitro,
                nitro_ws,
                proxy_config.as_ref(),
                &self.auth,
            ),
            connect_one(
                connect,
                dns_resolver,
                user_agent,
                enable_domain_fronting,
                tpm2snp,
                tpm2snp_ws,
                proxy_config.as_ref(),
                &self.auth,
            ),
        )
        .await;
        (sgx, nitro, tpm2snp)
    }
}

#[async_trait]
impl Backup for Svr3Client<'_, PreviousVersion> {
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
impl Restore for Svr3Client<'_, PreviousVersion> {
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
impl Remove for Svr3Client<'_, PreviousVersion> {
    async fn remove(&self) -> Result<(), Error> {
        empty_env::remove().await
    }
}

#[async_trait]
impl Query for Svr3Client<'_, PreviousVersion> {
    async fn query(&self) -> Result<u32, Error> {
        empty_env::query().await
    }
}

#[async_trait]
impl Rotate for Svr3Client<'_, PreviousVersion> {
    async fn rotate(
        &self,
        _share_set: OpaqueMaskedShareSet,
        _rng: &mut (impl CryptoRngCore + Send),
    ) -> Result<(), Error> {
        empty_env::rotate().await
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

    pub async fn rotate() -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use ::tokio; // otherwise ambiguous with the tokio submodule
    use assert_matches::assert_matches;
    use libsignal_net::chat::ChatServiceError;
    use test_case::test_case;

    use super::*;
    use crate::net::chat::UnauthenticatedChatConnection;

    #[test_case(Environment::Staging; "staging")]
    #[test_case(Environment::Prod; "prod")]
    fn can_create_connection_manager(env: Environment) {
        let _ = ConnectionManager::new(env, "test-user-agent");
    }

    // Normally we would write this test in the app languages, but it depends on timeouts.
    // Using a paused tokio runtime auto-advances time when there's no other work to be done.
    #[tokio::test(start_paused = true)]
    async fn cannot_connect_through_invalid_proxy() {
        let cm = ConnectionManager::new(Environment::Staging, "test-user-agent");
        cm.set_invalid_proxy();
        let err = UnauthenticatedChatConnection::connect(&cm)
            .await
            .map(|_| ())
            .expect_err("should fail to connect");
        assert_matches!(err, ChatServiceError::InvalidConnectionConfiguration);
    }

    #[test]
    fn network_change_event_debounced() {
        let cm = ConnectionManager::new(Environment::Staging, "test-user-agent");

        let fire_count = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let _subscription = {
            let fire_count = fire_count.clone();
            cm.network_change_event.subscribe(Box::new(move || {
                _ = fire_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }))
        };

        // The creation of the ConnectionManager sets the initial debounce timestamp,
        // so let's say our first even happens well after that.
        let start = Instant::now() + ConnectionManager::NETWORK_CHANGE_DEBOUNCE * 10;
        cm.on_network_change(start);
        assert_eq!(1, fire_count.load(std::sync::atomic::Ordering::SeqCst));

        cm.on_network_change(start);
        assert_eq!(1, fire_count.load(std::sync::atomic::Ordering::SeqCst));

        cm.on_network_change(start + ConnectionManager::NETWORK_CHANGE_DEBOUNCE / 2);
        assert_eq!(1, fire_count.load(std::sync::atomic::Ordering::SeqCst));

        cm.on_network_change(start + ConnectionManager::NETWORK_CHANGE_DEBOUNCE);
        assert_eq!(2, fire_count.load(std::sync::atomic::Ordering::SeqCst));

        cm.on_network_change(start);
        assert_eq!(2, fire_count.load(std::sync::atomic::Ordering::SeqCst));

        cm.on_network_change(start + ConnectionManager::NETWORK_CHANGE_DEBOUNCE * 3 / 2);
        assert_eq!(2, fire_count.load(std::sync::atomic::Ordering::SeqCst));

        cm.on_network_change(start + ConnectionManager::NETWORK_CHANGE_DEBOUNCE * 4);
        assert_eq!(3, fire_count.load(std::sync::atomic::Ordering::SeqCst));
    }
}
