//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use futures_util::stream::StreamExt as _;
use futures_util::Stream;
use libsignal_net::auth::Auth;
use libsignal_net::chat::{chat_service, Chat, ChatServiceWithDebugInfo};
use libsignal_net::env::{ConnectionConfig, DomainConfig, UserAgent};
use libsignal_net::infra::connection_manager::MultiRouteConnectionManager;
use libsignal_net::infra::errors::TransportConnectError;
use libsignal_net::infra::host::Host;
use libsignal_net::infra::utils::ObservableEvent;
use libsignal_net::infra::{AsyncDuplexStream, EndpointConnection};
use rand_core::OsRng;
use tokio::io::DuplexStream;
use tokio::time::Duration;
use tokio_stream::wrappers::UnboundedReceiverStream;
use warp::Filter as _;

mod behavior;
pub use behavior::Behavior;

mod connector;
pub use connector::FakeTransportConnector;

mod target;
pub use target::FakeTransportTarget;

/// Convenience alias for a dynamically-dispatched stream.
pub type FakeStream = Box<dyn AsyncDuplexStream>;

/// Produces an iterator with [`Behavior::ReturnStream`] for all proxy routes.
pub fn allow_proxy_hosts(
    domain_config: &DomainConfig,
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
            proxy
                .configs
                .iter()
                .flat_map(|config| {
                    config
                        .shuffled_connection_params("", None, &mut OsRng)
                        .map(|params| params.transport)
                })
                .map(|params| FakeTransportTarget {
                    host: params.tcp_host,
                    port: params.port,
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
    wait: Duration,
    error: fn() -> TransportConnectError,
) -> impl Iterator<Item = (FakeTransportTarget, Behavior)> {
    let DomainConfig {
        ip_v4,
        ip_v6,
        connect:
            ConnectionConfig {
                proxy,
                hostname,
                port,
                cert: _,
                confirmation_header_name: _,
            },
    } = domain_config;
    let direct_hosts = ip_v4
        .iter()
        .copied()
        .map(|ip| Host::Ip(ip.into()))
        .chain(ip_v6.iter().copied().map(|ip| Host::Ip(ip.into())))
        .chain([Host::Domain((*hostname).into())])
        .map(|host| FakeTransportTarget { host, port: *port });

    let targets = proxy
        .iter()
        .flat_map(|config| config.configs.iter())
        .flat_map(|config| {
            config
                .shuffled_connection_params("", None, &mut OsRng)
                .map(|params| params.transport)
        })
        .map(|params| FakeTransportTarget {
            host: params.tcp_host,
            port: params.port,
        })
        .chain(direct_hosts)
        .collect::<Vec<_>>();

    targets
        .into_iter()
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
    endpoint_connection: EndpointConnection<MultiRouteConnectionManager>,
}

impl FakeDeps {
    const MPSC_BUFFER_SIZE: usize = 128;

    pub fn new(
        chat_domain_config: &DomainConfig,
    ) -> (
        Self,
        UnboundedReceiverStream<(FakeTransportTarget, DuplexStream)>,
    ) {
        let (transport_connector, incoming_streams) = FakeTransportConnector::new([]);
        let endpoint_connection = libsignal_net::chat::endpoint_connection(
            &chat_domain_config.connect,
            &UserAgent::with_libsignal_version("libsignal test"),
            true,
            &ObservableEvent::new(),
        );

        (
            Self {
                transport_connector,
                endpoint_connection,
            },
            UnboundedReceiverStream::new(incoming_streams),
        )
    }

    pub fn make_chat(&self) -> Chat<impl ChatServiceWithDebugInfo, impl ChatServiceWithDebugInfo> {
        let (incoming_auth_tx, _incoming_auth_rx) =
            tokio::sync::mpsc::channel(Self::MPSC_BUFFER_SIZE);
        let (incoming_unauth_tx, _incoming_unauth_rx) =
            tokio::sync::mpsc::channel(Self::MPSC_BUFFER_SIZE);

        let auth = Auth {
            username: "user".to_owned(),
            password: "password".to_owned(),
        };

        const RECEIVE_STORIES: bool = true;

        chat_service(
            &self.endpoint_connection,
            self.transport_connector.clone(),
            incoming_auth_tx,
            incoming_unauth_tx,
            auth,
            RECEIVE_STORIES,
        )
    }
}

pub async fn connect_websockets_on_incoming<S: AsyncDuplexStream + 'static>(
    incoming_streams: impl Stream<Item = (FakeTransportTarget, S)> + Send,
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
