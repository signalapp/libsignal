//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::fmt::Display;
use std::net::Ipv6Addr;

use const_str::ip_addr;
use futures_util::stream::StreamExt as _;
use futures_util::Stream;
use itertools::Itertools as _;
use libsignal_net::chat::{self, ChatConnection, ChatServiceError, PendingChatConnection};
use libsignal_net::connect_state::{ConnectState, SUGGESTED_CONNECT_CONFIG};
use libsignal_net::env::{ConnectionConfig, DomainConfig, UserAgent};
use libsignal_net::infra::connection_manager::MultiRouteConnectionManager;
use libsignal_net::infra::dns::lookup_result::LookupResult;
use libsignal_net::infra::dns::DnsResolver;
use libsignal_net::infra::errors::TransportConnectError;
use libsignal_net::infra::host::Host;
use libsignal_net::infra::route::{DirectOrProxyProvider, DEFAULT_HTTPS_PORT};
use libsignal_net::infra::utils::ObservableEvent;
use libsignal_net::infra::{
    AsyncDuplexStream, DnsSource, EnableDomainFronting, EndpointConnection,
};
use tokio::time::Duration;
use tokio_stream::wrappers::UnboundedReceiverStream;
use warp::Filter as _;

mod behavior;
pub use behavior::Behavior;

mod connector;
pub use connector::{FakeTransportConnector, TransportConnectEvent, TransportConnectEventStage};

mod target;
pub use target::FakeTransportTarget;

use crate::fake_transport::connector::FakeTargetAndStream;

/// Convenience alias for a dynamically-dispatched stream.
pub type FakeStream = Box<dyn AsyncDuplexStream>;

/// Produces an iterator with [`Behavior::ReturnStream`] for all un-proxied
/// (direct and domain-fronted) routes.
pub fn allow_all_routes(
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
        .zip(std::iter::repeat(Behavior::ReturnStream(vec![])))
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
                confirmation_header_name: _,
                proxy,
            },
    } = domain_config;
    let allow_targets = proxy
        .iter()
        .flat_map(|proxy| {
            proxy.configs.iter().flat_map(|config| {
                config.hostnames().flat_map(|hostname| {
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
        .zip(std::iter::repeat(Behavior::ReturnStream(vec![])))
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

/// Collection of persistent structs used to create a [`Chat`] instance.
///
/// These values use internal reference counting to share data with created
/// `Chat` values, so keeping them around is useful.
pub struct FakeDeps {
    pub transport_connector: FakeTransportConnector,
    connect_state: tokio::sync::RwLock<ConnectState<FakeTransportConnector>>,
    pub dns_resolver: DnsResolver,
    chat_domain_config: DomainConfig,
    endpoint_connection: EndpointConnection<MultiRouteConnectionManager>,
    resolved_names: HashMap<&'static str, LookupResult>,
}

impl FakeDeps {
    pub fn new(
        chat_domain_config: &DomainConfig,
    ) -> (Self, UnboundedReceiverStream<FakeTargetAndStream>) {
        let (transport_connector, incoming_streams) = FakeTransportConnector::new([]);
        let endpoint_connection = libsignal_net::chat::endpoint_connection(
            &chat_domain_config.connect,
            &UserAgent::with_libsignal_version("libsignal test"),
            true,
            &ObservableEvent::new(),
        );

        let connect_state = ConnectState::new_with_transport_connector(
            SUGGESTED_CONNECT_CONFIG,
            transport_connector.clone(),
        );
        let resolved_names = fake_ips_for_names(chat_domain_config);
        let dns_resolver = DnsResolver::new_from_static_map(resolved_names.clone());
        (
            Self {
                transport_connector,
                endpoint_connection,
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

    pub async fn connect_chat(
        &self,
    ) -> Result<PendingChatConnection<FakeStream>, ChatServiceError> {
        let Self {
            endpoint_connection,
            connect_state,
            dns_resolver,
            transport_connector: _,
            resolved_names: _,
            chat_domain_config,
        } = self;
        let libsignal_net::infra::ws2::Config {
            local_idle_timeout,
            remote_idle_ping_timeout,
            remote_idle_disconnect_timeout: _,
        } = endpoint_connection.config.ws2_config();
        ChatConnection::start_connect_with_transport(
            connect_state,
            dns_resolver,
            DirectOrProxyProvider::maybe_proxied(
                chat_domain_config
                    .connect
                    .route_provider(EnableDomainFronting(true)),
                None,
            ),
            None,
            &UserAgent::with_libsignal_version("test"),
            chat::ws2::Config {
                local_idle_timeout,
                remote_idle_timeout: remote_idle_ping_timeout,
                initial_request_id: 0,
            },
            None,
            "fake chat",
        )
        .await
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
        .chain(
            proxy
                .iter()
                .flat_map(|proxy| proxy.configs.iter().flat_map(|config| config.hostnames())),
        )
        .zip(0..)
        .map(|(name, index)| {
            let mut segments = BASE_IP_ADDR.segments();
            *segments.last_mut().unwrap() = index;
            (
                name,
                LookupResult::new(DnsSource::Test, vec![], vec![segments.into()]),
            )
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
    warp::serve(filter)
        .run_incoming(incoming_streams.map(|(host, stream)| {
            log::info!("serving websocket to {host}");
            Ok::<_, std::io::Error>(stream)
        }))
        .await
}
