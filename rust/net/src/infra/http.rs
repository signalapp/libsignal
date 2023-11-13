//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use bytes::Bytes;
use http::request::Builder;
use http::response::Parts;
use http::uri::PathAndQuery;
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::http2;

use crate::infra::errors::NetError;
use crate::infra::tokio_executor::TokioExecutor;
use crate::infra::tokio_io::TokioIo;
use crate::infra::{AsyncDuplexStream, ConnectionParams, TransportConnector};

const HTTP_ALPN_H2_ONLY: &[u8] = b"\x02h2";

pub(crate) type Http2Connection<S> = http2::Connection<TokioIo<S>, Full<Bytes>, TokioExecutor>;

#[async_trait]
pub trait AggregatingHttpClient: Send + Sync + Clone {
    async fn send_request_aggregate_response(
        &mut self,
        path_and_query: PathAndQuery,
        request_builder: Builder,
        body: Bytes,
    ) -> Result<(Parts, Bytes), NetError>;
}

pub struct Http2Channel<T, S: AsyncDuplexStream + 'static> {
    pub aggregating_client: T,
    pub connection: Http2Connection<S>,
}

#[derive(Clone)]
pub struct AggregatingHttp2Client {
    service: http2::SendRequest<Full<Bytes>>,
    connection_params: ConnectionParams,
}

impl AggregatingHttp2Client {
    #[allow(dead_code)]
    pub fn new(
        service: http2::SendRequest<Full<Bytes>>,
        connection_params: ConnectionParams,
    ) -> Self {
        Self {
            service,
            connection_params,
        }
    }
}

#[async_trait]
impl AggregatingHttpClient for AggregatingHttp2Client {
    async fn send_request_aggregate_response(
        &mut self,
        path_and_query: PathAndQuery,
        request_builder: Builder,
        body: Bytes,
    ) -> Result<(Parts, Bytes), NetError> {
        let uri = format!(
            "https://{}:{}{}",
            self.connection_params.sni, self.connection_params.port, path_and_query
        );
        let request_builder = request_builder.uri(uri);
        let request_builder = self
            .connection_params
            .http_request_decorator
            .decorate_request(request_builder);

        let request = request_builder
            .body(Full::new(body))
            .map_err(|_| NetError::Failure)?;

        let res = self
            .service
            .send_request(request)
            .await
            .map_err(|_| NetError::Failure)?;

        let (parts, body) = res.into_parts();

        let content = match parts.headers.get(hyper::header::CONTENT_LENGTH) {
            Some(content_length_str) => {
                let content_length = content_length_str
                    .to_str()
                    .map_err(|_| NetError::ContentLengthHeaderInvalid)?
                    .parse::<usize>()
                    .map_err(|_| NetError::ContentLengthHeaderInvalid)?;
                Limited::new(body, content_length)
                    .collect()
                    .await
                    .map_err(|_| NetError::ContentLengthHeaderDoesntMatchDataSize)?
                    .to_bytes()
            }
            None => Bytes::new(),
        };

        Ok((parts, content))
    }
}

pub(crate) async fn http2_channel<C: TransportConnector>(
    transport_connector: &C,
    connection_params: &ConnectionParams,
) -> Result<Http2Channel<AggregatingHttp2Client, C::Stream>, NetError> {
    let ssl_stream = transport_connector
        .connect(connection_params, HTTP_ALPN_H2_ONLY)
        .await?;
    let io = TokioIo::new(ssl_stream);
    let (sender, connection) = http2::handshake::<_, _, Full<Bytes>>(TokioExecutor::new(), io)
        .await
        .map_err(|_| NetError::Http2FailedHandshake)?;

    let clone = connection_params.clone();
    Ok(Http2Channel {
        aggregating_client: AggregatingHttp2Client {
            service: sender,
            connection_params: ConnectionParams {
                sni: connection_params.host.clone(),
                ..clone
            },
        },
        connection,
    })
}
