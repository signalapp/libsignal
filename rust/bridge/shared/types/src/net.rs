//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::panic::RefUnwindSafe;
use std::sync::Arc;
use std::time::{Duration, Instant};

use libsignal_core::LogSafeDisplay as _;
use libsignal_net::connect_state::{
    ConnectState, ConnectionResources, DefaultConnectorFactory, PreconnectingFactory,
    SUGGESTED_CONNECT_CONFIG, SUGGESTED_TLS_PRECONNECT_LIFETIME,
};
use libsignal_net::enclave::{EnclaveEndpoint, EnclaveKind};
use libsignal_net::env::{Env, StaticIpOrder, UserAgent};
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::route::{
    ConnectionProxyConfig, DirectOrProxyMode, DirectOrProxyProvider, RouteProvider,
    RouteProviderExt as _, UnresolvedWebsocketServiceRoute,
};
use libsignal_net::infra::tcp_ssl::{InvalidProxyConfig, TcpSslConnector};
use libsignal_net::infra::{AsHttpHeader as _, EnableDomainFronting, OverrideNagleAlgorithm};
use rand::TryRngCore as _;

pub use self::remote_config::BuildVariant;
use self::remote_config::RemoteConfig;
use crate::*;

pub mod cdsi;
pub mod chat;
pub mod registration;
pub mod svr2;
pub mod svrb;

pub use libsignal_net::infra::EnforceMinimumTls;

pub mod remote_config;
pub mod tokio;
pub use tokio::TokioAsyncContext;

#[repr(u8)]
#[derive(Clone, Copy, strum::Display, derive_more::TryFrom)]
#[try_from(repr)]
pub enum Environment {
    Staging = 0,
    Prod = 1,
}

impl Environment {
    pub fn env(self) -> Env<'static> {
        match self {
            Self::Staging => libsignal_net::env::STAGING,
            Self::Prod => libsignal_net::env::PROD,
        }
    }
}

struct EndpointConnections {
    enable_fronting: EnableDomainFronting,
    enforce_minimum_tls: EnforceMinimumTls,
}

impl EndpointConnections {
    fn new(
        env: &Env<'static>,
        use_fallbacks: bool,
        enforce_minimum_tls: EnforceMinimumTls,
    ) -> Self {
        log::info!(
            "Creating endpoint connections (fallbacks {}) for {} and others",
            if use_fallbacks { "enabled" } else { "disabled" },
            // Note: this is *not* using log_safe_domain, because it is always the direct route.
            // Either it's chat.signal.org, chat.staging.signal.org, or something that indicates
            // testing. (Or the person running this isn't Signal.)
            env.chat_domain_config.connect.hostname
        );
        Self {
            enable_fronting: if use_fallbacks {
                EnableDomainFronting::OneDomainPerProxy
            } else {
                EnableDomainFronting::No
            },
            enforce_minimum_tls,
        }
    }
}

pub struct EnclaveConnectionResources<'a> {
    connect_state: &'a std::sync::Mutex<ConnectState<PreconnectingFactory>>,
    dns_resolver: &'a DnsResolver,
    network_change_event: ::tokio::sync::watch::Receiver<()>,
    confirmation_header_name: Option<&'static str>,
}

impl EnclaveConnectionResources<'_> {
    pub fn as_connection_resources(&self) -> ConnectionResources<'_, PreconnectingFactory> {
        let Self {
            connect_state,
            dns_resolver,
            network_change_event,
            confirmation_header_name,
        } = self;
        ConnectionResources {
            connect_state,
            dns_resolver,
            network_change_event,
            confirmation_header_name: confirmation_header_name.map(http::HeaderName::from_static),
        }
    }
}

pub struct ConnectionManager {
    env: Env<'static>,
    user_agent: UserAgent,
    dns_resolver: DnsResolver,
    remote_config: std::sync::Mutex<RemoteConfig>,
    connect: std::sync::Mutex<ConnectState<PreconnectingFactory>>,
    // We could split this up to a separate mutex on each kind of connection,
    // but we don't hold it for very long anyway (just enough to clone the Arc).
    endpoints: std::sync::Mutex<Arc<EndpointConnections>>,
    transport_connector: std::sync::Mutex<TcpSslConnector>,
    most_recent_network_change: std::sync::Mutex<Instant>,
    network_change_event_tx: ::tokio::sync::watch::Sender<()>,
}

impl RefUnwindSafe for ConnectionManager {}

impl ConnectionManager {
    pub fn new(
        environment: Environment,
        user_agent: &str,
        remote_config: HashMap<String, Arc<str>>,
        build_variant: BuildVariant,
    ) -> Self {
        log::info!("Initializing connection manager for {}...", environment);
        Self::new_from_static_environment(
            environment.env(),
            user_agent,
            remote_config,
            build_variant,
        )
    }

    pub fn new_from_static_environment(
        env: Env<'static>,
        user_agent: &str,
        remote_config: HashMap<String, Arc<str>>,
        build_variant: BuildVariant,
    ) -> Self {
        let (network_change_event_tx, network_change_event_rx) = ::tokio::sync::watch::channel(());
        let user_agent = UserAgent::with_libsignal_version(user_agent);

        let dns_resolver = DnsResolver::new_with_static_fallback(
            env.static_fallback(StaticIpOrder::Shuffled(&mut rand::rngs::OsRng.unwrap_err())),
            &network_change_event_rx,
        );
        let transport_connector =
            std::sync::Mutex::new(TcpSslConnector::new_direct(dns_resolver.clone()));
        let remote_config = RemoteConfig::new(remote_config, build_variant);
        let endpoints = std::sync::Mutex::new(
            EndpointConnections::new(&env, false, EnforceMinimumTls::Yes).into(),
        );
        Self {
            env,
            endpoints,
            user_agent,
            remote_config: remote_config.into(),
            connect: ConnectState::new_with_transport_connector(
                SUGGESTED_CONNECT_CONFIG,
                PreconnectingFactory::new(
                    DefaultConnectorFactory,
                    SUGGESTED_TLS_PRECONNECT_LIFETIME,
                ),
            ),
            dns_resolver,
            transport_connector,
            most_recent_network_change: Instant::now().into(),
            network_change_event_tx,
        }
    }

    pub fn set_proxy_mode(&self, proxy_mode: DirectOrProxyMode) {
        log::info!("set_proxy_mode({})", proxy_mode.log_safe_display());
        let mut guard = self.transport_connector.lock().expect("not poisoned");
        guard.set_proxy_mode(proxy_mode);
    }

    pub fn set_invalid_proxy(&self) {
        let mut guard = self.transport_connector.lock().expect("not poisoned");
        guard.set_invalid();
    }

    /// Resets the route configuration to include or exclude censorship circumvention routes.
    ///
    /// This is not itself a network change event; existing working connections are expected to
    /// continue to work, and existing failing connections will continue to fail.
    pub fn set_censorship_circumvention_enabled(&self, enable: bool) {
        let reflector_proxies = enable.then(|| {
            let providers = (self.env.reflector_providers)();
            assert!(
                !providers.is_empty(),
                // This is not *technically* true, because the `localhost_test_env_with_ports` contains an emptly list
                // of reflector providers, but that's only used in tests.
                "reflector providers are configured at compile time, so they should never be empty"
            );
            ConnectionProxyConfig::Reflector(providers)
        });
        log::info!("set_censorship_circumvention_enabled({enable})");
        self.transport_connector
            .lock()
            .expect("not poisoned")
            .set_reflector(reflector_proxies);
    }

    pub fn is_using_proxy(&self) -> Result<bool, InvalidProxyConfig> {
        let guard = self.transport_connector.lock().expect("not poisoned");
        guard
            .proxy()
            .map(|proxy| !matches!(proxy, DirectOrProxyMode::DirectOnly))
    }

    pub fn set_ipv6_enabled(&self, ipv6_enabled: bool) {
        let mut guard = self.transport_connector.lock().expect("not poisoned");
        guard.set_ipv6_enabled(ipv6_enabled);
        self.connect
            .lock()
            .expect("not poisoned")
            .route_resolver
            .allow_ipv6 = ipv6_enabled;
    }

    pub fn set_remote_config(
        &self,
        remote_config: HashMap<String, Arc<str>>,
        build_variant: BuildVariant,
    ) {
        *self.remote_config.lock().expect("not poisoned") =
            RemoteConfig::new(remote_config, build_variant);
    }

    fn chat_grpc_overrides(&self) -> HashMap<&'static str, libsignal_net::chat::GrpcOverride> {
        use libsignal_net::chat::GrpcOverride;
        let guard = self.remote_config.lock().expect("not poisoned");
        guard
            .iter_enabled()
            .filter_map(|(k, v)| {
                k.as_grpc_request_name().map(|k| {
                    (
                        k,
                        if **v == *"ws" {
                            GrpcOverride::UseWs
                        } else {
                            GrpcOverride::UseGrpc
                        },
                    )
                })
            })
            .collect()
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
        self.network_change_event_tx.send_replace(());
        self.dns_resolver.on_network_change(now.into());
        self.connect
            .lock()
            .expect("not poisoned")
            .network_changed(now.into());
    }

    pub fn enclave_connection_resources(
        &self,
        enclave: &EnclaveEndpoint<impl EnclaveKind>,
    ) -> Result<
        (
            EnclaveConnectionResources<'_>,
            impl RouteProvider<Route = UnresolvedWebsocketServiceRoute> + '_,
        ),
        InvalidProxyConfig,
    > {
        let proxy_mode: DirectOrProxyMode =
            (&*self.transport_connector.lock().expect("not poisoned")).try_into()?;

        let (enable_domain_fronting, enforce_minimum_tls) = {
            let guard = self.endpoints.lock().expect("not poisoned");
            (guard.enable_fronting, guard.enforce_minimum_tls)
        };
        let route_provider = enclave
            .enclave_websocket_provider_with_options(
                enable_domain_fronting,
                enforce_minimum_tls,
                OverrideNagleAlgorithm::OverrideToOff,
            )
            .map_routes(|mut route| {
                route.fragment.headers.extend([self.user_agent.as_header()]);
                route
            });
        let confirmation_header_name = enclave.domain_config.connect.confirmation_header_name;
        Ok((
            EnclaveConnectionResources {
                connect_state: &self.connect,
                dns_resolver: &self.dns_resolver,
                network_change_event: self.network_change_event_tx.subscribe(),
                confirmation_header_name,
            },
            DirectOrProxyProvider {
                inner: route_provider,
                mode: proxy_mode,
            },
        ))
    }

    pub fn env(&self) -> &Env<'static> {
        &self.env
    }
}

bridge_as_handle!(ConnectionManager);
bridge_as_handle!(ConnectionProxyConfig);

#[cfg(test)]
mod test {
    use ::tokio; // otherwise ambiguous with the tokio submodule
    use assert_matches::assert_matches;
    use libsignal_net::chat::ConnectError;
    use test_case::{test_case, test_matrix};

    use super::*;
    use crate::net::chat::UnauthenticatedChatConnection;

    #[test_case(Environment::Staging; "staging")]
    #[test_case(Environment::Prod; "prod")]
    fn can_create_connection_manager(env: Environment) {
        let _ = ConnectionManager::new(
            env,
            "test-user-agent",
            Default::default(),
            BuildVariant::Production,
        );
    }

    #[test_case(
        Environment::Staging,
        "/tls-tunnel-staging",
        "reflector-staging-signal.global.ssl.fastly.net"
        ; "staging"
    )]
    #[test_case(
        Environment::Prod,
        "/tls-tunnel",
        "reflector-signal.global.ssl.fastly.net"
        ; "prod"
    )]
    fn censorship_circumvention_uses_environment_specific_routes(
        env: Environment,
        expected_endpoint: &str,
        expected_http_host: &str,
    ) {
        let cm = ConnectionManager::new(
            env,
            "test-user-agent",
            Default::default(),
            BuildVariant::Production,
        );
        cm.set_censorship_circumvention_enabled(true);

        let guard = cm.transport_connector.lock().expect("not poisoned");
        let proxy_mode = guard.proxy().expect("valid proxy config");
        assert_matches!(
            proxy_mode,
            DirectOrProxyMode::DirectThenProxy(ConnectionProxyConfig::Reflector(providers))
                if providers.iter().all(|p| p.endpoint.as_str() == expected_endpoint)
                    && providers[0].http_host == expected_http_host
        );
    }

    #[test_matrix((true, false))]
    fn censorship_circumvention_toggle_does_not_disturb_existing_http_proxy(enable: bool) {
        use libsignal_net::infra::host::Host;
        use libsignal_net::infra::route::HttpProxy;
        use nonzero_ext::nonzero;

        let cm = ConnectionManager::new(
            Environment::Prod,
            "test-user-agent",
            Default::default(),
            BuildVariant::Production,
        );

        let http_proxy = ConnectionProxyConfig::Http(HttpProxy {
            proxy_host: Host::Domain(Arc::from("proxy.example.com")),
            proxy_port: nonzero!(8080_u16),
            proxy_tls: None,
            proxy_authorization: None,
            resolve_hostname_locally: false,
        });
        cm.set_proxy_mode(DirectOrProxyMode::DirectThenProxy(http_proxy));

        cm.set_censorship_circumvention_enabled(enable);
        let guard = cm.transport_connector.lock().expect("not poisoned");
        assert_matches!(
            guard.proxy().expect("valid proxy config"),
            DirectOrProxyMode::DirectThenProxy(ConnectionProxyConfig::Http(_))
        );
    }

    #[test_matrix([true, false])]
    fn censorship_circumvention_proxy_toggle_does_not_disturb_invalid_proxy_state(enable: bool) {
        let cm = ConnectionManager::new(
            Environment::Prod,
            "test-user-agent",
            Default::default(),
            BuildVariant::Production,
        );
        cm.set_invalid_proxy();

        cm.set_censorship_circumvention_enabled(enable);
        assert_matches!(
            cm.transport_connector.lock().expect("not poisoned").proxy(),
            Err(_)
        );
    }

    #[test]
    fn censorship_circumvention_proxy_disable_sets_direct_only() {
        let cm = ConnectionManager::new(
            Environment::Prod,
            "test-user-agent",
            Default::default(),
            BuildVariant::Production,
        );
        cm.set_censorship_circumvention_enabled(true);
        cm.set_censorship_circumvention_enabled(false);

        let guard = cm.transport_connector.lock().expect("not poisoned");
        assert_matches!(guard.proxy(), Ok(DirectOrProxyMode::DirectOnly));
    }

    #[test]
    fn censorship_circumvention_survives_explicit_proxy_set_then_clear() {
        use libsignal_net::infra::host::Host;
        use libsignal_net::infra::route::HttpProxy;
        use nonzero_ext::nonzero;

        let cm = ConnectionManager::new(
            Environment::Prod,
            "test-user-agent",
            Default::default(),
            BuildVariant::Production,
        );

        cm.set_censorship_circumvention_enabled(true);

        // An explicit user proxy takes precedence over the reflector.
        cm.set_proxy_mode(DirectOrProxyMode::DirectThenProxy(
            ConnectionProxyConfig::Http(HttpProxy {
                proxy_host: Host::Domain(Arc::from("proxy.example.com")),
                proxy_port: nonzero!(8080_u16),
                proxy_tls: None,
                proxy_authorization: None,
                resolve_hostname_locally: false,
            }),
        ));
        assert_matches!(
            cm.transport_connector
                .lock()
                .expect("not poisoned")
                .proxy()
                .expect("valid proxy config"),
            DirectOrProxyMode::DirectThenProxy(ConnectionProxyConfig::Http(_))
        );

        // ... but clearing it falls back to the reflector.
        cm.set_proxy_mode(DirectOrProxyMode::DirectOnly);
        assert_matches!(
            cm.transport_connector
                .lock()
                .expect("not poisoned")
                .proxy()
                .expect("valid proxy config"),
            DirectOrProxyMode::DirectThenProxy(ConnectionProxyConfig::Reflector(_))
        );
    }

    // Normally we would write this test in the app languages, but it depends on timeouts.
    // Using a paused tokio runtime auto-advances time when there's no other work to be done.
    #[tokio::test(start_paused = true)]
    async fn cannot_connect_through_invalid_proxy() {
        let cm = ConnectionManager::new(
            Environment::Staging,
            "test-user-agent",
            Default::default(),
            BuildVariant::Production,
        );
        cm.set_invalid_proxy();
        let err = UnauthenticatedChatConnection::connect(&cm, Default::default())
            .await
            .map(|_| ())
            .expect_err("should fail to connect");
        assert_matches!(err, ConnectError::InvalidConnectionConfiguration);
    }

    #[test]
    fn network_change_event_debounced() {
        let cm = ConnectionManager::new(
            Environment::Staging,
            "test-user-agent",
            Default::default(),
            BuildVariant::Production,
        );

        let mut fired = cm.network_change_event_tx.subscribe();
        assert_matches!(fired.has_changed(), Ok(false));

        // The creation of the ConnectionManager sets the initial debounce timestamp,
        // so let's say our first even happens well after that.
        let start = Instant::now() + ConnectionManager::NETWORK_CHANGE_DEBOUNCE * 10;
        cm.on_network_change(start);
        assert_matches!(fired.has_changed(), Ok(true));
        fired.mark_unchanged();

        cm.on_network_change(start);
        assert_matches!(fired.has_changed(), Ok(false));

        cm.on_network_change(start + ConnectionManager::NETWORK_CHANGE_DEBOUNCE / 2);
        assert_matches!(fired.has_changed(), Ok(false));

        cm.on_network_change(start + ConnectionManager::NETWORK_CHANGE_DEBOUNCE);
        assert_matches!(fired.has_changed(), Ok(true));
        fired.mark_unchanged();

        cm.on_network_change(start);
        assert_matches!(fired.has_changed(), Ok(false));

        cm.on_network_change(start + ConnectionManager::NETWORK_CHANGE_DEBOUNCE * 3 / 2);
        assert_matches!(fired.has_changed(), Ok(false));

        cm.on_network_change(start + ConnectionManager::NETWORK_CHANGE_DEBOUNCE * 4);
        assert_matches!(fired.has_changed(), Ok(true));
        fired.mark_unchanged();
    }
}
