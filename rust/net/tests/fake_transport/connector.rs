//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::fmt::Debug;
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use futures_util::TryFutureExt as _;
use libsignal_net::infra::errors::TransportConnectError;
use libsignal_net_infra::host::Host;
use libsignal_net_infra::route::{
    ConnectionProxyRoute, Connector, TcpRoute, TlsRouteFragment, TransportRoute, UsePreconnect,
};
use libsignal_net_infra::ws::WebSocketTransportStream;
use tokio::io::DuplexStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::time::Instant;

use super::{Behavior, FakeStream, FakeTransportTarget};

mod replace;
pub use replace::*;

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
    TcpConnect(Option<Host<Arc<str>>>),
    TlsHandshake(Host<Arc<str>>),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TransportConnectEventStage {
    Start,
    End,
}

pub type FakeTargetAndStream = (Host<Arc<str>>, DuplexStream);

type TransportEventAtTime = ((TransportConnectEvent, TransportConnectEventStage), Instant);

pub struct FakeConnector<C> {
    replaced: C,
    server_stream_sender: UnboundedSender<(Host<Arc<str>>, DuplexStream)>,
}

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

    pub fn replaced_stateless<R: ReplaceStatelessConnectorsWithFake>(
        &self,
        replace_in: R,
    ) -> FakeConnector<R::Replacement> {
        FakeConnector {
            replaced: replace_in.replace_with_fake(self.clone()),
            server_stream_sender: self.server_stream_sender.clone(),
        }
    }

    pub fn set_behaviors(&self, items: impl IntoIterator<Item = (FakeTransportTarget, Behavior)>) {
        self.connect_behavior.lock().unwrap().extend(items)
    }

    fn connect_with_events<'a>(
        &self,
        over: FakeStream,
        target: FakeTransportTarget,
        log_tag: &'a str,
    ) -> impl Future<Output = Result<FakeStream, TransportConnectError>> + Send + use<'_, 'a> {
        let Self {
            server_stream_sender: _,
            connect_behavior,
            recorded_events,
        } = self;

        let behavior = connect_behavior
            .lock()
            .unwrap()
            .get(&target)
            .cloned()
            .unwrap_or(Behavior::DelayForever);

        async move {
            log::info!(
                "[{log_tag}] fake connector \"connecting\" {target}, override: {behavior:?}",
            );

            let stage = TransportConnectEvent::from(target.clone());
            recorded_events.lock().unwrap().push((
                (stage.clone(), TransportConnectEventStage::Start),
                Instant::now(),
            ));
            let stream_modifier = behavior.apply().await?;
            recorded_events
                .lock()
                .unwrap()
                .push(((stage, TransportConnectEventStage::End), Instant::now()));

            log::info!("[{log_tag}] finished connecting {target}");

            Ok(stream_modifier(over))
        }
    }
}

impl<C> Connector<UsePreconnect<TransportRoute>, ()> for FakeConnector<C>
where
    C: Connector<TransportRoute, FakeStream> + Send,
{
    type Connection = C::Connection;

    type Error = C::Error;

    fn connect_over(
        &self,
        (): (),
        route: UsePreconnect<TransportRoute>,
        log_tag: &str,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let Self {
            replaced,
            server_stream_sender,
        } = self;
        let (local, remote) = tokio::io::duplex(MAX_BUF_SIZE);
        let sni = route.inner.fragment.sni.clone();

        replaced
            .connect_over(Box::new(local), route.inner, log_tag)
            .inspect_ok(|_| {
                server_stream_sender.send((sni, remote)).unwrap();
            })
    }
}

const MAX_BUF_SIZE: usize = 512 * 1024;

impl Connector<TcpRoute<IpAddr>, FakeStream> for FakeTransportConnector {
    type Connection = FakeStream;

    type Error = TransportConnectError;

    fn connect_over(
        &self,
        client_stream: FakeStream,
        tcp: TcpRoute<IpAddr>,
        log_tag: &str,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let target = FakeTransportTarget::from(tcp.clone());

        self.connect_with_events(Box::new(client_stream), target, log_tag)
    }
}

impl Connector<ConnectionProxyRoute<IpAddr>, FakeStream> for FakeTransportConnector {
    type Connection = FakeStream;

    type Error = TransportConnectError;

    fn connect_over(
        &self,
        client_stream: FakeStream,
        proxy: ConnectionProxyRoute<IpAddr>,
        log_tag: &str,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let target = FakeTransportTarget::from_proxy_route(&proxy);

        self.connect_with_events(Box::new(client_stream), target, log_tag)
    }
}

impl<S: WebSocketTransportStream> Connector<TlsRouteFragment, S> for FakeTransportConnector {
    type Connection = FakeStream;

    type Error = TransportConnectError;

    fn connect_over(
        &self,
        inner: S,
        tls: TlsRouteFragment,
        log_tag: &str,
    ) -> impl Future<Output = Result<Self::Connection, Self::Error>> + Send {
        let target = FakeTransportTarget::Tls {
            sni: tls.sni.clone(),
        };

        self.connect_with_events(Box::new(inner), target, log_tag)
    }
}

impl From<FakeTransportTarget> for TransportConnectEvent {
    fn from(target: FakeTransportTarget) -> Self {
        match target {
            FakeTransportTarget::TcpThroughProxy { host, .. } => Self::TcpConnect(host),
            FakeTransportTarget::Tcp { host, .. } => Self::TcpConnect(Some(host.into())),
            FakeTransportTarget::Tls { sni } => Self::TlsHandshake(sni),
        }
    }
}
