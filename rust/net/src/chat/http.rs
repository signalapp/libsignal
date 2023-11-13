//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::Duration;

use async_trait::async_trait;
use futures_util::TryFutureExt;

use crate::chat::errors::ChatNetworkError;
use crate::chat::{ChatService, Request, ResponseProto};
use crate::infra::errors::NetError;
use crate::infra::http::{
    http2_channel, AggregatingHttp2Client, AggregatingHttpClient, Http2Channel, Http2Connection,
};
use crate::infra::reconnect::{ServiceConnector, ServiceStatus};
use crate::infra::{AsyncDuplexStream, ConnectionParams, TransportConnector};
use crate::utils::timeout;

#[derive(Clone)]
pub struct ChatOverHttp2ServiceConnector<C> {
    transport_connector: C,
}

impl<C> ChatOverHttp2ServiceConnector<C> {
    pub fn new(transport_connector: C) -> Self {
        Self {
            transport_connector,
        }
    }
}

#[async_trait]
impl<C: TransportConnector> ServiceConnector for ChatOverHttp2ServiceConnector<C> {
    type Service = ChatOverHttp2;
    type Channel = Http2Channel<AggregatingHttp2Client, C::Stream>;
    type Error = ChatNetworkError;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::Error> {
        let connect_future = http2_channel(&self.transport_connector, connection_params)
            .map_err(ChatNetworkError::FailedToConnectHttp);
        timeout(
            Duration::from_secs(2),
            ChatNetworkError::Timeout,
            connect_future,
        )
        .await
    }

    fn start_service(&self, channel: Self::Channel) -> (Self::Service, ServiceStatus<Self::Error>) {
        let Http2Channel {
            aggregating_client: request_sender,
            connection,
        } = channel;
        let service_status = ServiceStatus::new();
        start_event_listener(connection, service_status.clone());
        (ChatOverHttp2 { request_sender }, service_status)
    }
}

#[async_trait]
impl ChatService for ChatOverHttp2 {
    async fn send(
        &self,
        msg: Request,
        timeout_duration: Duration,
    ) -> Result<ResponseProto, ChatNetworkError> {
        let (path, builder, body) = msg.into_parts();
        let mut request_sender = self.request_sender.clone();
        let response_future = request_sender.send_request_aggregate_response(path, builder, body);
        match timeout(timeout_duration, NetError::Timeout, response_future).await {
            Ok((parts, aggregated_body)) => {
                let status: Option<u32> = Some(parts.status.as_u16().into());
                let message: Option<String> = Some(parts.status.to_string());
                let body = match aggregated_body.len() {
                    0 => None,
                    _ => Some(aggregated_body.to_vec()),
                };

                let headers: Vec<String> = parts
                    .headers
                    .iter()
                    .map(|header| {
                        format!(
                            "{}: {}",
                            header.0.as_str(),
                            header.1.to_str().expect("has header value")
                        )
                    })
                    .collect();

                Ok(ResponseProto {
                    id: None,
                    status,
                    message,
                    body,
                    headers,
                })
            }
            Err(err) => Err(ChatNetworkError::FailedToSendHttp(err)),
        }
    }
}

#[derive(Clone)]
pub struct ChatOverHttp2 {
    request_sender: AggregatingHttp2Client,
}

fn start_event_listener(
    connection: Http2Connection<impl AsyncDuplexStream>,
    service_status: ServiceStatus<ChatNetworkError>,
) {
    tokio::spawn(async move {
        enum Event {
            Cancellation,
            ChannelClosed(Result<(), hyper::Error>),
        }
        let outcome = match tokio::select! {
            _ = service_status.stopped() => Event::Cancellation,
            r = connection => Event::ChannelClosed(r),
        } {
            Event::Cancellation => ChatNetworkError::ChannelClosedByLocalPeer,
            Event::ChannelClosed(Ok(_)) => ChatNetworkError::ChannelClosedByRemotePeer,
            Event::ChannelClosed(Err(e)) => ChatNetworkError::ChannelClosedWithError(e),
        };
        service_status.stop_service_with_error(outcome);
    });
}
