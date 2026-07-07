//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::convert::Infallible;
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use futures_util::{Sink, Stream};
use http_body_util::BodyExt;
use http_body_util::combinators::BoxBody;
use libsignal_net_infra::TransportInfo;
use libsignal_net_infra::http_client::{Http2Client, Http2Connector};
use libsignal_net_infra::route::{Connector, GetCurrentInterface, HttpRouteFragment, HttpVersion};
use libsignal_net_infra::stream::StreamWithFixedTransportInfo;
use libsignal_net_infra::utils::no_network_change_events;
use pin_project::pin_project;
use prost::Message;
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::chat::{
    ChatConnection, ConnectionInfo, GrpcBody, GrpcOverride, MessageProto, RequestProto,
    ResponseProto, ws,
};
use crate::connect_state::RouteInfo;
use crate::env::ALERT_HEADER_NAME;

/// The remote end of a fake connection to the chat server.
#[derive(Debug)]
pub struct FakeChatRemote {
    tx: tokio::sync::mpsc::UnboundedSender<Result<tungstenite::Message, tungstenite::Error>>,
    rx: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<tungstenite::Message>>,
    grpc: tokio::sync::Mutex<FakeGrpcRemote>,
}

#[derive(Debug)]
struct GrpcResponseSender(
    tokio::sync::oneshot::Sender<http::Response<BoxBody<bytes::Bytes, Infallible>>>,
);
/// We never use this without consuming it, so unwinding isn't an issue.
impl std::panic::UnwindSafe for GrpcResponseSender {}

/// The remote end of a fake gRPC connection to the chat server.
#[derive(Debug)]
pub struct FakeGrpcRemote {
    incoming: tokio::sync::mpsc::UnboundedReceiver<(
        http::Request<hyper::body::Incoming>,
        GrpcResponseSender,
    )>,
    response_map: HashMap<u64, GrpcResponseSender>,
    next_id: u64,
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
        grpc_overrides: impl IntoIterator<Item = &'static str>,
        alerts: impl IntoIterator<Item = &'a str>,
    ) -> (Self, FakeChatRemote) {
        let (tx_to_local, rx_from_remote) = tokio::sync::mpsc::unbounded_channel();
        let (tx_to_remote, rx_from_local) = tokio::sync::mpsc::unbounded_channel();

        let incoming = UnboundedReceiverStream::new(rx_from_remote);
        let outgoing = futures_util::sink::unfold(tx_to_remote, |tx, message| async move {
            tx.send(message).map_err(|_send_failed| {
                tungstenite::Error::Io(std::io::ErrorKind::BrokenPipe.into())
            })?;
            Ok(tx)
        });
        let local = StreamSink(incoming, outgoing, PhantomData);

        let (h2_connection, grpc_remote) = Self::h2_connection(&tokio_runtime);

        let remote = FakeChatRemote {
            tx: tx_to_local,
            rx: rx_from_local.into(),
            grpc: grpc_remote.into(),
        };

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
                Some(h2_connection),
                no_network_change_events(),
                listener,
            ),
            connection_info,
            grpc_overrides: HashMap::from_iter(
                grpc_overrides
                    .into_iter()
                    .map(|api| (api, GrpcOverride::UseGrpc)),
            ),
            // This isn't perfect, but without it we can't test APIs that rely on knowing the self
            // ACI, so it's better that we set it to *something*.
            self_aci: Some(libsignal_core::Aci::from_uuid_bytes([0xff; 16])),
        };
        (chat, remote)
    }

    fn h2_connection(
        tokio_runtime: &tokio::runtime::Handle,
    ) -> (Http2Client<GrpcBody>, FakeGrpcRemote) {
        let (remote_incoming_req_tx, remote_incoming_req_rx) =
            tokio::sync::mpsc::unbounded_channel();
        let (client_io, server_io) = tokio::io::duplex(65536);

        _ = tokio_runtime.spawn(
            hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(
                    hyper_util::rt::TokioIo::new(server_io),
                    hyper::service::service_fn(move |req| {
                        let remote_incoming_req_tx = remote_incoming_req_tx.clone();
                        async move {
                            let (response_tx, response_rx) = tokio::sync::oneshot::channel::<
                                http::Response<BoxBody<bytes::Bytes, Infallible>>,
                            >();
                            remote_incoming_req_tx
                                .send((req, GrpcResponseSender(response_tx)))
                                .map_err(|_| "server shutdown")?;
                            response_rx.await.map_err(|_| "server shutdown")
                        }
                    }),
                ),
        );

        let _make_tokio_runtime_available_for_connect = tokio_runtime.enter();
        let client = futures::executor::block_on(Http2Connector::new().connect_over(
            StreamWithFixedTransportInfo::new(
                client_io,
                TransportInfo {
                    local_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
                    remote_addr: SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0),
                },
            ),
            HttpRouteFragment {
                host_header: "fake-chat.signal.org".into(),
                path_prefix: Default::default(),
                http_version: Some(HttpVersion::Http2),
                front_name: None,
            },
            "fake h2",
        ))
        .expect("valid");

        let remote = FakeGrpcRemote {
            incoming: remote_incoming_req_rx,
            response_map: Default::default(),
            next_id: 1,
        };

        (client, remote)
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
        let message =
            match tokio::time::timeout(Duration::from_secs(3), self.rx.lock().await.recv()).await {
                Ok(Some(message)) => message,
                Ok(None) => return Ok(None),
                Err(_) => panic!("receive_request timed out, did you actually send a WS request?"),
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

    pub async fn grpc(&self) -> tokio::sync::MutexGuard<'_, FakeGrpcRemote> {
        self.grpc.lock().await
    }
}

impl FakeGrpcRemote {
    pub async fn receive_request(
        &mut self,
    ) -> Result<Option<(u64, http::Request<bytes::Bytes>)>, ReceiveRequestError> {
        log::debug!("waiting for next request");
        let (req, response_tx) =
            match tokio::time::timeout(Duration::from_secs(3), self.incoming.recv()).await {
                Ok(Some(next)) => next,
                Ok(None) => return Ok(None),
                Err(_) => {
                    panic!("receive_request timed out, did you actually send a gRPC request?")
                }
            };

        let id = self.next_id;
        self.response_map.insert(id, response_tx);
        self.next_id += 1;

        let (head, body) = req.into_parts();
        let body = body
            .collect()
            .await
            .map_err(|_| ReceiveRequestError::InvalidWebsocketMessageType)?
            .to_bytes();
        Ok(Some((id, http::Request::from_parts(head, body))))
    }

    pub fn send_response(
        &mut self,
        which: u64,
        response: http::Response<impl IntoHttpBody>,
    ) -> Result<(), Disconnected> {
        log::debug!("sending response");
        let Some(GrpcResponseSender(response_tx)) = self.response_map.remove(&which) else {
            // TODO: wrong error
            return Err(Disconnected);
        };
        response_tx
            .send(response.map(|body| body.into_http_body()))
            .map_err(|_| Disconnected)
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

#[derive(Clone, Default)]
pub struct BodyWithTrailers {
    pub data: Vec<u8>,
    pub trailers: http::HeaderMap,
}

pub trait IntoHttpBody {
    fn into_http_body(self) -> BoxBody<bytes::Bytes, Infallible>;
}

impl IntoHttpBody for Vec<u8> {
    fn into_http_body(self) -> BoxBody<bytes::Bytes, Infallible> {
        bytes::Bytes::from(self).into_http_body()
    }
}

impl IntoHttpBody for bytes::Bytes {
    fn into_http_body(self) -> BoxBody<bytes::Bytes, Infallible> {
        http_body_util::Full::new(self).boxed()
    }
}

impl IntoHttpBody for BodyWithTrailers {
    fn into_http_body(self) -> BoxBody<bytes::Bytes, Infallible> {
        http_body_util::Full::new(bytes::Bytes::from(self.data))
            .with_trailers(std::future::ready(Some(Ok(self.trailers))))
            .boxed()
    }
}
