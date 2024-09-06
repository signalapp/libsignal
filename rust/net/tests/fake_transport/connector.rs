//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use libsignal_net::infra::errors::TransportConnectError;
use libsignal_net::infra::{
    Alpn, ConnectionInfo, DnsSource, RouteType, StreamAndInfo, TransportConnectionParams,
    TransportConnector,
};
use tokio::io::DuplexStream;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::{Behavior, FakeStream, FakeTransportTarget};

/// Fake [`TransportConnector`] implementation.
///
/// The behavior when a new connection is requested is controlled per-host by
/// [Self::connect_behavior]. If a stream is established, the "local" end is
/// returned to the caller and the "remote" end is sent to the receiver on the
/// other end of [Self::server_stream_sender].
#[derive(Clone)]
pub struct FakeTransportConnector {
    server_stream_sender: UnboundedSender<(FakeTransportTarget, DuplexStream)>,
    connect_behavior: Arc<Mutex<HashMap<FakeTransportTarget, Behavior>>>,
}

impl FakeTransportConnector {
    pub fn new<T: IntoIterator<Item = (FakeTransportTarget, Behavior)>>(
        connect_behavior: T,
    ) -> (Self, UnboundedReceiver<(FakeTransportTarget, DuplexStream)>) {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let connector = Self {
            server_stream_sender: sender,
            connect_behavior: Arc::new(Mutex::new(connect_behavior.into_iter().collect())),
        };
        (connector, receiver)
    }

    pub fn set_behaviors(&self, items: impl IntoIterator<Item = (FakeTransportTarget, Behavior)>) {
        self.connect_behavior.lock().unwrap().extend(items)
    }
}

const MAX_BUF_SIZE: usize = 512 * 1024;

#[async_trait]
impl TransportConnector for FakeTransportConnector {
    type Stream = FakeStream;

    async fn connect(
        &self,
        connection_params: &TransportConnectionParams,
        _alpn: Alpn,
    ) -> Result<StreamAndInfo<Self::Stream>, TransportConnectError> {
        let Self {
            server_stream_sender,
            connect_behavior,
        } = self;

        let TransportConnectionParams {
            tcp_host,
            port,
            sni: _,
            certs: _,
        } = connection_params;
        let fake_host = FakeTransportTarget {
            host: tcp_host.clone(),
            port: *port,
        };

        let behavior = connect_behavior
            .lock()
            .unwrap()
            .get(&fake_host)
            .cloned()
            .unwrap_or(Behavior::DelayForever);
        log::info!("fake connector \"connecting\" to {fake_host}, overrides: {behavior:?}");

        let stream_modifiers = behavior.apply().await?;

        log::info!("connected {fake_host} at transport level");

        let (client_stream, server_stream) = tokio::io::duplex(MAX_BUF_SIZE);

        let client_stream = stream_modifiers
            .into_iter()
            .fold(Box::new(client_stream) as Box<_>, |stream, f| f(stream));

        server_stream_sender
            .send((fake_host, server_stream))
            .unwrap();

        Ok(StreamAndInfo(
            client_stream,
            ConnectionInfo {
                route_type: RouteType::Direct,
                dns_source: DnsSource::Static,
                address: tcp_host.clone(),
            },
        ))
    }
}
