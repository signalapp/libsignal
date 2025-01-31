//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::fmt::Debug;
use std::marker::PhantomData;
use std::time::Duration;

use futures_util::{Sink, SinkExt as _, Stream};
use libsignal_net_infra::{IpType, TransportInfo};
use pin_project::pin_project;
use prost::Message;
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::chat::{ws2, ChatConnection, ConnectionInfo};
use crate::connect_state::RouteInfo;
use crate::proto;

pub type MessageProto = proto::chat_websocket::WebSocketMessage;
pub type RequestProto = proto::chat_websocket::WebSocketRequestMessage;
pub type ResponseProto = proto::chat_websocket::WebSocketResponseMessage;
pub type ChatMessageType = proto::chat_websocket::web_socket_message::Type;

/// The remote end of a fake connection to the chat server.
#[derive(Debug)]
pub struct FakeChatRemote {
    tx: tokio::sync::mpsc::UnboundedSender<Result<tungstenite::Message, tungstenite::Error>>,
}

/// Error returned when a send fails because the client end has finished.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Disconnected;

impl ChatConnection {
    /// Creates a `ChatConnection` connected to a fake remote end.
    pub fn new_fake(
        tokio_runtime: tokio::runtime::Handle,
        listener: ws2::EventListener,
    ) -> (Self, FakeChatRemote) {
        let (tx_to_local, rx_from_remote) = tokio::sync::mpsc::unbounded_channel();

        let remote = FakeChatRemote { tx: tx_to_local };

        let incoming = UnboundedReceiverStream::new(rx_from_remote);
        let outgoing = futures_util::sink::drain().sink_map_err(|never| match never {});
        let local = StreamSink(incoming, outgoing, PhantomData);

        let connection_info = ConnectionInfo {
            route_info: RouteInfo::fake(),
            transport_info: TransportInfo {
                ip_version: IpType::V4,
                local_port: 0,
            },
        };
        let log_tag = "fake chat".into();
        let config = crate::chat::ws2::Config {
            local_idle_timeout: Duration::from_secs(86400),
            remote_idle_timeout: Duration::from_secs(86400),
            initial_request_id: 0,
        };
        let chat = Self {
            inner: crate::chat::ws2::Chat::new(tokio_runtime, local, config, log_tag, listener),
            connection_info,
        };
        (chat, remote)
    }
}

impl FakeChatRemote {
    /// Send a [`RequestProto`] to the client.
    pub fn send_request(&self, request: RequestProto) -> Result<(), Disconnected> {
        log::debug!("sending binary RequestProto");
        let proto = MessageProto {
            r#type: Some(crate::proto::chat_websocket::web_socket_message::Type::Request.into()),
            request: Some(request),
            response: None,
        };
        self.tx
            .send(Ok(tungstenite::Message::Binary(proto.encode_to_vec())))
            .map_err(|_failed_send| Disconnected)
    }

    /// Send a close frame to the client.
    pub fn send_close(&self, code: Option<u16>) -> Result<(), Disconnected> {
        self.tx
            .send(Ok(tungstenite::Message::Close(code.map(|code| {
                tungstenite::protocol::CloseFrame {
                    code: code.into(),
                    reason: "manual closure".into(),
                }
            }))))
            .map_err(|_failed_send| Disconnected)
    }
}

/// Combines [`Stream`] and [`Sink`] implementers into a single `Stream + Sink` type.
#[pin_project]
struct StreamSink<Tx, Rx, RxItem>(#[pin] Tx, #[pin] Rx, PhantomData<RxItem>);

impl<Tx: Stream, Rx: Sink<RxItem>, RxItem> Stream for StreamSink<Tx, Rx, RxItem> {
    type Item = Tx::Item;

    fn poll_next(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.project().0.poll_next(cx)
    }
}

impl<Tx: Stream, Rx: Sink<RxItem>, RxItem> Sink<RxItem> for StreamSink<Tx, Rx, RxItem> {
    type Error = Rx::Error;

    fn poll_ready(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.project().1.poll_ready(cx)
    }

    fn start_send(self: std::pin::Pin<&mut Self>, item: RxItem) -> Result<(), Self::Error> {
        self.project().1.start_send(item)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.project().1.poll_flush(cx)
    }

    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.project().1.poll_close(cx)
    }
}
