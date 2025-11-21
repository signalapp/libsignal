//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::fmt::Display;
use std::net::Ipv6Addr;

use const_str::ip_addr;
use futures_util::Stream;
use futures_util::stream::StreamExt as _;
use itertools::Itertools as _;
use libsignal_net::chat::{
    self, ChatConnection, PendingChatConnection, RECOMMENDED_CHAT_WS_CONFIG,
};
use libsignal_net::connect_state::{
    ConnectState, ConnectionResources, DefaultConnectorFactory, DefaultTransportConnector,
    SUGGESTED_CONNECT_CONFIG,
};
use libsignal_net::env::constants::CHAT_WEBSOCKET_PATH;
use libsignal_net::env::{ConnectionConfig, DomainConfig, UserAgent};
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::dns::lookup_result::LookupResult;
use libsignal_net::infra::errors::TransportConnectError;
use libsignal_net::infra::host::Host;
use libsignal_net::infra::route::{ConnectorFactory, DEFAULT_HTTPS_PORT, DirectOrProxyProvider};
pub use libsignal_net::infra::testutil::fake_transport::FakeTransportTarget;
use libsignal_net::infra::{AsyncDuplexStream, EnableDomainFronting, OverrideNagleAlgorithm};
use libsignal_net_infra::route::{Connector, TransportRoute, UsePreconnect};
use libsignal_net_infra::utils::no_network_change_events;
use libsignal_net_infra::ws::WebSocketTransportStream;
use tokio::time::Duration;
use tokio_stream::wrappers::UnboundedReceiverStream;
use warp::Filter as _;

use crate::fake_transport::connector::{
    FakeConnector, FakeTargetAndStream, ReplaceStatelessConnectorsWithFake,
};

mod behavior;
pub use behavior::Behavior;

mod connector;
pub use connector::{FakeTransportConnector, TransportConnectEvent, TransportConnectEventStage};

/// Convenience alias for a dynamically-dispatched stream.
///
/// We use this for streams other than websocket transports, but [`WebSocketTransportStream`] is
/// still a handy *maximal* set of requirements.
pub type FakeStream = Box<dyn WebSocketTransportStream>;

/// Produces an iterator with just direct routes (without chaining domain fronted routes).
pub fn only_direct_routes(
    domain_config: &DomainConfig,
    resolved_names: &HashMap<&'static str, LookupResult>,
) -> impl Iterator<Item = (FakeTransportTarget, Behavior)> {
    let DomainConfig {
        ip_v4: _,
        ip_v6: _,
        connect:
            ConnectionConfig {
                port,
                hostname,
                cert: _,
                min_tls_version: _,
                http_version: _,
                confirmation_header_name: _,
                proxy: _,
            },
    } = domain_config;
    let direct_ips = &resolved_names[hostname];

    direct_ips
        .iter()
        .map(|ip| FakeTransportTarget::Tcp {
            host: ip,
            port: *port,
        })
        // Collect intermediates so the returned iterator isn't borrowing.
        .collect_vec()
        .into_iter()
        .chain([FakeTransportTarget::Tls {
            sni: Host::Domain((*hostname).into()),
        }])
        .zip(std::iter::repeat(Behavior::ReturnStream(None)))
}

/// Produces an iterator with [`Behavior::ReturnStream`] for all un-proxied (direct) and domain-fronted routes.
pub fn allow_all_routes(
    domain_config: &DomainConfig,
    resolved_names: &HashMap<&'static str, LookupResult>,
) -> impl Iterator<Item = (FakeTransportTarget, Behavior)> {
    only_direct_routes(domain_config, resolved_names)
        .chain(allow_domain_fronting(domain_config, resolved_names))
}

/// Produces an iterator with [`Behavior::ReturnStream`] for all domain-fronted
/// routes.
pub fn allow_domain_fronting(
    domain_config: &DomainConfig,
    resolved_names: &HashMap<&'static str, LookupResult>,
) -> impl Iterator<Item = (FakeTransportTarget, Behavior)> {
    let DomainConfig {
        ip_v4: _,
        ip_v6: _,
        connect:
            ConnectionConfig {
                port: _,
                hostname: _,
                cert: _,
                min_tls_version: _,
                http_version: _,
                confirmation_header_name: _,
                proxy,
            },
    } = domain_config;
    let allow_targets = proxy
        .iter()
        .flat_map(|proxy| {
            proxy.configs.iter().flat_map(|config| {
                config.hostnames().iter().flat_map(|&hostname| {
                    let ips = &resolved_names[hostname];
                    ips.iter().flat_map(|ip| {
                        [
                            FakeTransportTarget::Tcp {
                                host: ip,
                                port: DEFAULT_HTTPS_PORT,
                            },
                            FakeTransportTarget::Tls {
                                sni: Host::Domain(hostname.into()),
                            },
                        ]
                    })
                })
            })
        })
        .collect::<Vec<_>>();

    allow_targets
        .into_iter()
        .zip(std::iter::repeat(Behavior::ReturnStream(None)))
}

/// Produces an iterator that, for all routes, delays then returns an error.
pub fn error_all_hosts_after(
    domain_config: &DomainConfig,
    resolved_names: &HashMap<&'static str, LookupResult>,
    wait: Duration,
    error: fn() -> TransportConnectError,
) -> impl Iterator<Item = (FakeTransportTarget, Behavior)> {
    allow_all_routes(domain_config, resolved_names)
        .map(|(target, _behavior)| target)
        .zip(std::iter::repeat_with(move || Behavior::Delay {
            delay: wait,
            then: Box::new(Behavior::Fail(error)),
        }))
}

struct ReplacingConnectorFactory(FakeTransportConnector, DefaultConnectorFactory);

/// Collection of persistent structs used to create a [`Chat`] instance.
///
/// These values use internal reference counting to share data with created
/// `Chat` values, so keeping them around is useful.
pub struct FakeDeps {
    pub transport_connector: FakeTransportConnector,
    connect_state: std::sync::Mutex<ConnectState<ReplacingConnectorFactory>>,
    pub dns_resolver: DnsResolver,
    chat_domain_config: DomainConfig,
    resolved_names: HashMap<&'static str, LookupResult>,
}

impl FakeDeps {
    pub fn new(
        chat_domain_config: &DomainConfig,
    ) -> (Self, UnboundedReceiverStream<FakeTargetAndStream>) {
        let (transport_connector, incoming_streams) = FakeTransportConnector::new([]);

        let connector_factory =
            ReplacingConnectorFactory(transport_connector.clone(), DefaultConnectorFactory);
        let connect_state =
            ConnectState::new_with_transport_connector(SUGGESTED_CONNECT_CONFIG, connector_factory);
        let resolved_names = fake_ips_for_names(chat_domain_config);
        let dns_resolver = DnsResolver::new_from_static_map(resolved_names.clone());
        (
            Self {
                transport_connector,
                connect_state,
                dns_resolver,
                chat_domain_config: chat_domain_config.clone(),
                resolved_names,
            },
            UnboundedReceiverStream::new(incoming_streams),
        )
    }

    pub fn static_ip_map(&self) -> &HashMap<&'static str, LookupResult> {
        &self.resolved_names
    }

    pub async fn connect_chat(&self) -> Result<PendingChatConnection, chat::ConnectError> {
        let Self {
            connect_state,
            dns_resolver,
            transport_connector: _,
            resolved_names: _,
            chat_domain_config,
        } = self;
        let connection_resources = ConnectionResources {
            connect_state,
            dns_resolver,
            network_change_event: &no_network_change_events(),
            confirmation_header_name: None,
        };

        ChatConnection::start_connect_with_transport(
            connection_resources,
            DirectOrProxyProvider::direct(chat_domain_config.connect.route_provider(
                EnableDomainFronting::OneDomainPerProxy,
                OverrideNagleAlgorithm::UseSystemDefault,
            )),
            CHAT_WEBSOCKET_PATH,
            &UserAgent::with_libsignal_version("test"),
            RECOMMENDED_CHAT_WS_CONFIG,
            None,
            "fake chat",
        )
        .await
    }
}

impl ConnectorFactory<UsePreconnect<TransportRoute>> for ReplacingConnectorFactory {
    type Connector = FakeConnector<
        <DefaultTransportConnector as ReplaceStatelessConnectorsWithFake>::Replacement,
    >;

    type Connection = <Self::Connector as Connector<UsePreconnect<TransportRoute>, ()>>::Connection;

    fn make(&self) -> Self::Connector {
        self.0
            .replaced_stateless(ConnectorFactory::<TransportRoute>::make(&self.1))
    }
}

/// Produce a mapping from name to IP addresses to seed a [`DnsResolver`].
fn fake_ips_for_names(domain_config: &DomainConfig) -> HashMap<&'static str, LookupResult> {
    // Assign IP addresses from the documentation space (RFC
    // 3849) since we're not actually going to try connecting to
    // them.
    const BASE_IP_ADDR: Ipv6Addr = ip_addr!(v6, "2001:db8::");
    let ConnectionConfig {
        hostname, proxy, ..
    } = &domain_config.connect;

    [*hostname]
        .into_iter()
        .chain(proxy.iter().flat_map(|proxy| {
            proxy
                .configs
                .iter()
                .flat_map(|config| config.hostnames().iter().copied())
        }))
        .zip(0..)
        .map(|(name, index)| {
            let mut segments = BASE_IP_ADDR.segments();
            *segments.last_mut().unwrap() = index;
            (name, LookupResult::new(vec![], vec![segments.into()]))
        })
        .collect()
}

pub async fn connect_websockets_on_incoming<S: AsyncDuplexStream + 'static, T: Display>(
    incoming_streams: impl Stream<Item = (T, S)> + Send,
) {
    let filter = warp::any().and(warp::ws()).map(|ws: warp::ws::Ws| {
        ws.on_upgrade(|_ws| {
            log::info!("serving websocket");
            std::future::pending()
        })
    });
    let mut incoming_streams = std::pin::pin!(incoming_streams);
    while let Some((host, stream)) = incoming_streams.next().await {
        log::info!("serving websocket to {host}");
        tokio::spawn(hyper::server::conn::http1::Builder::new().serve_connection(
            hyper_util::rt::TokioIo::new(stream),
            hyper_util::service::TowerToHyperService::new(warp::service(filter)),
        ));
    }
}
