//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::future::Future;
use std::sync::{Arc, Mutex};

use futures_util::{StreamExt as _, TryStreamExt as _};
use itertools::Itertools;
use libsignal_net::infra::errors::TransportConnectError;
use libsignal_net_infra::host::Host;
use libsignal_net_infra::route::{
    ConnectionProxyRoute, Connector, ConnectorFactory, DirectOrProxyRoute, HttpProxyRouteFragment,
    HttpsProxyRoute, ProxyTarget, SocksRoute, TcpRoute, TlsRoute, TransportRoute,
};
use tokio::io::DuplexStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::time::Instant;

use super::{Behavior, FakeStream, FakeTransportTarget};

/// Fake [`TransportConnector`] implementation.
///
/// The behavior when a new connection is requested is controlled per-host by
/// [Self::connect_behavior]. If a stream is established, the "local" end is
/// returned to the caller and the "remote" end is sent to the receiver on the
/// other end of [Self::server_stream_sender].
#[derive(Clone)]
pub struct FakeTransportConnector {
    pub recorded_events: Arc<Mutex<Vec<TransportEventAtTime>>>,
    server_stream_sender: UnboundedSender<(Host<Arc<str>>, DuplexStream)>,
    connect_behavior: Arc<Mutex<HashMap<FakeTransportTarget, Behavior>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportConnectEvent {
    TcpConnect(Host<Arc<str>>),
    TlsHandshake(Host<Arc<str>>),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransportConnectEventStage {
    Start,
    End,
}

pub type FakeTargetAndStream = (Host<Arc<str>>, DuplexStream);

type TransportEventAtTime = ((TransportConnectEvent, TransportConnectEventStage), Instant);

impl FakeTransportConnector {
    pub fn new<T: IntoIterator<Item = (FakeTransportTarget, Behavior)>>(
        connect_behavior: T,
    ) -> (Self, UnboundedReceiver<FakeTargetAndStream>) {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let connector = Self {
            server_stream_sender: sender,
            connect_behavior: Arc::new(Mutex::new(connect_behavior.into_iter().collect())),
            recorded_events: Default::default(),
        };
        (connector, receiver)
    }

    pub fn set_behaviors(&self, items: impl IntoIterator<Item = (FakeTransportTarget, Behavior)>) {
        self.connect_behavior.lock().unwrap().extend(items)
    }
}

const MAX_BUF_SIZE: usize = 512 * 1024;

impl Connector<TransportRoute, ()> for FakeTransportConnector {
    type Connection = FakeStream;

    type Error = TransportConnectError;

    fn connect_over(
        &self,
        (): (),
        route: TransportRoute,
        log_tag: Arc<str>,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let Self {
            server_stream_sender,
            connect_behavior,
            recorded_events,
        } = self;

        let targets = FakeTransportTarget::from_route(&route);

        let guard = connect_behavior.lock().unwrap();
        let behaviors = targets.map(|target| {
            let behavior = guard
                .get(&target)
                .cloned()
                .unwrap_or(Behavior::DelayForever);
            (target, behavior)
        });

        let fake_host = route.fragment.sni.clone();

        async move {
            log::info!(
                "[{log_tag}] fake connector \"connecting\" along {}, overrides: {behaviors:?}",
                DescribeRoute(&route),
            );

            let stream_modifiers: Vec<_> = futures_util::stream::iter(behaviors)
                .then(move |(target, behavior)| async move {
                    let stage = TransportConnectEvent::for_target(target);
                    recorded_events.lock().unwrap().push((
                        (stage.clone(), TransportConnectEventStage::Start),
                        Instant::now(),
                    ));
                    let r = behavior.apply().await?;
                    recorded_events.lock().unwrap().push((
                        (stage.clone(), TransportConnectEventStage::End),
                        Instant::now(),
                    ));
                    Ok::<_, TransportConnectError>(r)
                })
                .try_collect()
                .await?;
            let stream_modifiers = stream_modifiers.into_iter().flatten().collect_vec();

            log::info!("[{log_tag}] connected {fake_host} at transport level");

            let (client_stream, server_stream) = tokio::io::duplex(MAX_BUF_SIZE);

            let client_stream = stream_modifiers
                .into_iter()
                .fold(Box::new(client_stream) as Box<_>, |stream, f| f(stream));

            server_stream_sender
                .send((fake_host, server_stream))
                .unwrap();

            Ok(client_stream)
        }
    }
}

/// A convenience rather than using a separate type.
impl<R, Inner> ConnectorFactory<R, Inner> for FakeTransportConnector
where
    Self: Connector<R, Inner>,
{
    type Connector = Self;
    type Connection = <Self as Connector<R, Inner>>::Connection;

    fn make(&self) -> Self::Connector {
        self.clone()
    }
}

impl TransportConnectEvent {
    fn for_target(target: FakeTransportTarget) -> Self {
        match target {
            FakeTransportTarget::TcpThroughProxy { host, .. } => {
                TransportConnectEvent::TcpConnect(host)
            }
            FakeTransportTarget::Tcp { host, .. } => TransportConnectEvent::TcpConnect(host.into()),
            FakeTransportTarget::Tls { sni } => TransportConnectEvent::TlsHandshake(sni),
        }
    }
}

fn target_host_port(route: &TransportRoute) -> TcpRoute<Host<Arc<str>>> {
    let (port, address) = match &route.inner {
        DirectOrProxyRoute::Direct(tcp) => (tcp.port, tcp.address.into()),
        DirectOrProxyRoute::Proxy(proxy) => match proxy {
            ConnectionProxyRoute::Tls {
                proxy: TlsRoute { inner, .. },
            }
            | ConnectionProxyRoute::Tcp { proxy: inner } => (inner.port, inner.address.into()),
            ConnectionProxyRoute::Https(HttpsProxyRoute {
                fragment:
                    HttpProxyRouteFragment {
                        target_port,
                        target_host,
                        ..
                    },
                ..
            })
            | ConnectionProxyRoute::Socks(SocksRoute {
                target_port,
                target_addr: target_host,
                ..
            }) => (
                *target_port,
                match target_host {
                    ProxyTarget::ResolvedLocally(ip) => (*ip).into(),
                    ProxyTarget::ResolvedRemotely { name } => Host::Domain(name.clone()),
                },
            ),
        },
    };
    TcpRoute { address, port }
}

struct DescribeRoute<'a>(&'a TransportRoute);

impl Display for DescribeRoute<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(TlsRoute { fragment, inner }) = self;
        write!(f, "{} ", fragment.sni)?;

        let TcpRoute { address, port } = target_host_port(self.0);
        match inner {
            DirectOrProxyRoute::Direct(_) => f.write_str("at ")?,
            DirectOrProxyRoute::Proxy(_) => f.write_str("proxied to ")?,
        };
        write!(f, "{address}:{port}")
    }
}
