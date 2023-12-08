//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::Duration;

use async_trait::async_trait;

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
    type Error = NetError;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::Error> {
        let connect_future = http2_channel(&self.transport_connector, connection_params);
        timeout(Duration::from_secs(2), NetError::Timeout, connect_future).await
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
    ) -> Result<ResponseProto, NetError> {
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
            Err(err) => Err(err),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChatOverHttp2 {
    request_sender: AggregatingHttp2Client,
}

fn start_event_listener(
    connection: Http2Connection<impl AsyncDuplexStream>,
    service_status: ServiceStatus<NetError>,
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
            Event::Cancellation => NetError::ChannelClosedByLocalPeer,
            Event::ChannelClosed(Ok(_)) => NetError::ChannelClosedByRemotePeer,
            Event::ChannelClosed(Err(_)) => NetError::ChannelClosedWithError,
        };
        service_status.stop_service_with_error(outcome);
    });
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::chat::test::shared::{connection_manager, test_request};
    use crate::infra::test::shared::{InMemoryWarpConnector, NoReconnectService, TIMEOUT_DURATION};
    use http::Method;
    use tokio::time::Instant;
    use warp::Filter;

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn h2_service_correctly_handles_multiple_in_flight_requests() {
        // creating a server that responds to requests with 200 after some request processing time
        let start = Instant::now();
        const REQUEST_PROCESSING_DURATION: Duration =
            Duration::from_millis(TIMEOUT_DURATION.as_millis() as u64 / 2);

        let h2_server = warp::get().then(|| async move {
            tokio::time::sleep(REQUEST_PROCESSING_DURATION).await;
            warp::reply()
        });
        let h2_connector =
            ChatOverHttp2ServiceConnector::new(InMemoryWarpConnector::new(h2_server));
        let h2_chat = NoReconnectService::start(h2_connector, connection_manager()).await;

        let req1 = test_request(Method::GET, "/1");
        let response1_future = h2_chat.send(req1, TIMEOUT_DURATION);

        let req2 = test_request(Method::GET, "/2");
        let response2_future = h2_chat.send(req2, TIMEOUT_DURATION);

        // Making sure that at this point the clock has not advanced from the initial instant.
        // This is a way to indirectly make sure that neither of the futures is yet completed.
        assert_eq!(start, Instant::now());

        let (response1, response2) = tokio::join!(response1_future, response2_future);
        assert_eq!(200, response1.unwrap().status.unwrap());
        assert_eq!(200, response2.unwrap().status.unwrap());

        // And now making sure that both requests were in fact processed asynchronously,
        // i.e. one was not blocked on the other.
        assert_eq!(start + REQUEST_PROCESSING_DURATION, Instant::now());
    }
}
