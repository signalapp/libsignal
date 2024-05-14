//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::infra::{Alpn, ConnectionParams, StreamAndInfo, TransportConnector};
use bytes::Bytes;
use http::request::Builder;
use http::response::Parts;
use http::uri::PathAndQuery;
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};

#[derive(displaydoc::Display, Debug)]
pub enum HttpError {
    /// SSL handshake failed
    SslHandshakeFailed,
    /// HTTP2 handshake failed
    Http2HandshakeFailed,
    /// Failed to create HTTP request
    FailedToCreateRequest,
    /// Failed to send request or receive the response
    SendRequestError,
    /// `Content-Length` header has invalid value
    ContentLengthHeaderInvalid,
    /// Failed while reading response body with the known `Content-Length`
    FailedToReadContentOfKnownSize,
    /// Failed while reading response body with the unknown size
    FailedToReadContentOfUnknownSize,
    /// Content larger than max size configured for the client
    ResponseTooLarge,
}

#[derive(Debug, Clone)]
pub struct AggregatingHttp2Client {
    service: http2::SendRequest<Full<Bytes>>,
    connection_params: ConnectionParams,
    max_response_size: usize,
}

impl AggregatingHttp2Client {
    pub async fn send_request_aggregate_response(
        &self,
        path_and_query: PathAndQuery,
        request_builder: Builder,
        body: Bytes,
    ) -> Result<(Parts, Bytes), HttpError> {
        let uri = format!(
            "https://{}:{}{}",
            self.connection_params.sni, self.connection_params.port, path_and_query
        );
        let request_builder = request_builder.uri(uri);
        let request_builder = self
            .connection_params
            .http_request_decorator
            .decorate_request(request_builder);

        let content_length = body.len();
        let request = request_builder
            .header(http::header::CONTENT_LENGTH, content_length)
            .body(Full::new(body))
            .map_err(|_| HttpError::FailedToCreateRequest)?;

        let res = self
            .service
            .clone()
            .send_request(request)
            .await
            .map_err(|_| HttpError::SendRequestError)?;

        let (parts, body) = res.into_parts();

        let content_length = parts
            .headers
            .get(hyper::header::CONTENT_LENGTH)
            .map(|c| {
                c.to_str()
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or(HttpError::ContentLengthHeaderInvalid)
            })
            .transpose()?;

        let content = match content_length {
            Some(content_length) if content_length > self.max_response_size => {
                return Err(HttpError::ResponseTooLarge)
            }
            Some(content_length) => Limited::new(body, content_length)
                .collect()
                .await
                .map_err(|_| HttpError::FailedToReadContentOfKnownSize)?,
            _ => Limited::new(body, self.max_response_size)
                .collect()
                .await
                .map_err(|_| HttpError::FailedToReadContentOfUnknownSize)?,
        }
        .to_bytes();

        Ok((parts, content))
    }
}

pub(crate) async fn http2_client<C: TransportConnector>(
    transport_connector: &C,
    connection_params: ConnectionParams,
    max_response_size: usize,
) -> Result<AggregatingHttp2Client, HttpError> {
    let StreamAndInfo(ssl_stream, info) = transport_connector
        .connect(&connection_params, Alpn::Http2)
        .await
        .map_err(|e| {
            log::error!("error: {}", e);
            HttpError::SslHandshakeFailed
        })?;
    let io = TokioIo::new(ssl_stream);
    let (sender, connection) = http2::handshake::<_, _, Full<Bytes>>(TokioExecutor::new(), io)
        .await
        .map_err(|_| HttpError::Http2HandshakeFailed)?;

    // Starting a thread to drive client connection events.
    // The task will complete once the connection is closed due to an error
    // or if all clients are dropped.
    tokio::spawn(async move {
        match connection.await {
            Ok(_) => log::info!("HTTP2 connection [{}] closed", info.description()),
            Err(err) => log::warn!("HTTP2 connection [{}] failed: {}", info.description(), err),
        }
    });

    let clone = connection_params.clone();
    Ok(AggregatingHttp2Client {
        service: sender,
        connection_params: ConnectionParams {
            sni: connection_params.host.clone(),
            ..clone
        },
        max_response_size,
    })
}
