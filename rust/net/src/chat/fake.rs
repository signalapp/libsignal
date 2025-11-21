//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use futures_util::{Sink, Stream};
use libsignal_net_infra::TransportInfo;
use libsignal_net_infra::route::GetCurrentInterface;
use libsignal_net_infra::utils::no_network_change_events;
use pin_project::pin_project;
use prost::Message;
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::chat::{ChatConnection, ConnectionInfo, MessageProto, RequestProto, ResponseProto, ws};
use crate::connect_state::RouteInfo;
use crate::env::ALERT_HEADER_NAME;

/// The remote end of a fake connection to the chat server.
#[derive(Debug)]
pub struct FakeChatRemote {
    tx: tokio::sync::mpsc::UnboundedSender<Result<tungstenite::Message, tungstenite::Error>>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<tungstenite::Message>>,
}

/// Error returned when a send fails because the client end has finished.
#[derive(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct Disconnected;

/// Error returned when a receive fails because the request is invalid.
#[derive(Debug, derive_more::From)]
pub enum ReceiveRequestError {
    InvalidProto(String),
    InvalidWebsocketMessageType,
    GotResponse,
}

impl ChatConnection {
    /// Creates a `ChatConnection` connected to a fake remote end.
    pub fn new_fake<'a>(
        tokio_runtime: tokio::runtime::Handle,
        listener: ws::EventListener,
        alerts: impl IntoIterator<Item = &'a str>,
    ) -> (Self, FakeChatRemote) {
        let (tx_to_local, rx_from_remote) = tokio::sync::mpsc::unbounded_channel();
        let (tx_to_remote, rx_from_local) = tokio::sync::mpsc::unbounded_channel();

        let remote = FakeChatRemote {
            tx: tx_to_local,
            rx: rx_from_local.into(),
        };

        let incoming = UnboundedReceiverStream::new(rx_from_remote);
        let outgoing = futures_util::sink::unfold(tx_to_remote, |tx, message| async move {
            tx.send(message).map_err(|_send_failed| {
                tungstenite::Error::Io(std::io::ErrorKind::BrokenPipe.into())
            })?;
            Ok(tx)
        });
        let local = StreamSink(incoming, outgoing, PhantomData);

        let connection_info = ConnectionInfo {
            route_info: RouteInfo::fake(),
            transport_info: TransportInfo {
                local_addr: (Ipv4Addr::UNSPECIFIED, 0).into(),
                remote_addr: (Ipv4Addr::UNSPECIFIED, 0).into(),
            },
        };
        let log_tag = "fake chat".into();
        let config = crate::chat::ws::Config {
            local_idle_timeout: Duration::from_secs(86400),
            post_request_interface_check_timeout: Duration::MAX,
            remote_idle_timeout: Duration::from_secs(86400),
            initial_request_id: 0,
        };
        let headers = http::HeaderMap::from_iter(alerts.into_iter().map(|alert| {
            (
                http::HeaderName::from_static(ALERT_HEADER_NAME),
                http::HeaderValue::from_str(alert)
                    .expect("valid headers only for a fake connection"),
            )
        }));
        let chat = Self {
            inner: crate::chat::ws::Chat::new(
                tokio_runtime,
                local,
                headers,
                config,
                crate::chat::ws::ConnectionConfig {
                    log_tag,
                    post_request_interface_check_timeout: config
                        .post_request_interface_check_timeout,
                    transport_info: connection_info.transport_info.clone(),
                    get_current_interface: FakeCurrentInterface,
                },
                None,
                no_network_change_events(),
                listener,
            ),
            connection_info,
        };
        (chat, remote)
    }
}

struct FakeCurrentInterface;
impl GetCurrentInterface for FakeCurrentInterface {
    type Representation = IpAddr;

    fn get_interface_for(
        &self,
        _target: IpAddr,
    ) -> impl Future<Output = Self::Representation> + Send {
        std::future::ready(Ipv4Addr::UNSPECIFIED.into())
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
            .send(Ok(tungstenite::Message::Binary(
                proto.encode_to_vec().into(),
            )))
            .map_err(|_failed_send| Disconnected)
    }

    /// Send a [`ResponseProto`] to the client.
    pub fn send_response(&self, response: ResponseProto) -> Result<(), Disconnected> {
        log::debug!("sending binary ResponseProto");
        let proto = MessageProto {
            r#type: Some(crate::proto::chat_websocket::web_socket_message::Type::Response.into()),
            request: None,
            response: Some(response),
        };
        self.tx
            .send(Ok(tungstenite::Message::Binary(
                proto.encode_to_vec().into(),
            )))
            .map_err(|_failed_send| Disconnected)
    }

    pub async fn receive_request(&self) -> Result<Option<RequestProto>, ReceiveRequestError> {
        log::debug!("waiting for next request");
        let Some(message) = self.rx.lock().await.recv().await else {
            return Ok(None);
        };
        let proto = match message {
            tungstenite::Message::Close(None)
            | tungstenite::Message::Close(Some(tungstenite::protocol::CloseFrame {
                code: tungstenite::protocol::frame::coding::CloseCode::Normal,
                reason: _,
            })) => return Ok(None),
            tungstenite::Message::Binary(message) => ws::decode_and_validate(&message)?,
            _ => return Err(ReceiveRequestError::InvalidWebsocketMessageType),
        };
        match proto {
            ws::ChatMessageProto::Request(request) => Ok(Some(request)),
            ws::ChatMessageProto::Response(_) => Err(ReceiveRequestError::GotResponse),
        }
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

impl From<ws::ChatProtoDataError> for ReceiveRequestError {
    fn from(value: ws::ChatProtoDataError) -> Self {
        Self::InvalidProto(value.to_string())
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
