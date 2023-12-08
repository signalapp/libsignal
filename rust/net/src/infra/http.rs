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

#[derive(Clone, Debug)]
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

        let content_length = parts
            .headers
            .get(hyper::header::CONTENT_LENGTH)
            .map(|c| {
                c.to_str()
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or(NetError::ContentLengthHeaderInvalid)
            })
            .transpose()?;

        let content = match content_length {
            Some(content_length) => Limited::new(body, content_length)
                .collect()
                .await
                .map_err(|_| NetError::ContentLengthHeaderDoesntMatchDataSize)?,
            _ => body
                .collect()
                .await
                .map_err(|_| NetError::HttpInterruptedDuringReceive)?,
        }
        .to_bytes();

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

#[cfg(test)]
mod test {
    use std::collections::HashMap;

    use lazy_static::lazy_static;
    use warp::Filter as _;

    use crate::infra::test::shared::InMemoryWarpConnector;

    use super::*;

    const FAKE_PORT: u16 = 1212;
    lazy_static! {
        static ref FAKE_CONNECTION_PARAMS: ConnectionParams = ConnectionParams {
            sni: "sni".into(),
            host: "host".into(),
            port: FAKE_PORT,
            http_request_decorator: Default::default(),
            certs: crate::infra::certs::RootCertificates::Native,
            dns_resolver: crate::infra::dns::DnsResolver::Static
        };
    }

    #[tokio::test]
    async fn aggregating_client_accepts_response_without_content_length() {
        // HTTP servers are not required to send a content-length header.
        const FAKE_BODY: &str = "body";
        const FAKE_PATH_AND_QUERY: &str = "/path?query=true";

        let h2_server = warp::get().and(warp::path("path")).and(warp::query()).then(
            |query: HashMap<String, String>| async move {
                assert_eq!(query.get("query").map(String::as_str), Some("true"));
                warp::reply::html(FAKE_BODY)
            },
        );

        let transport_connector = InMemoryWarpConnector::new(h2_server);

        let Http2Channel {
            mut aggregating_client,
            connection,
        } = http2_channel(&transport_connector, &FAKE_CONNECTION_PARAMS)
            .await
            .expect("can connect");

        let _connection_task = tokio::spawn(connection);

        let response = aggregating_client
            .send_request_aggregate_response(
                PathAndQuery::from_static(FAKE_PATH_AND_QUERY),
                Builder::new(),
                Bytes::new(),
            )
            .await
            .expect("gets response");

        let (_parts, content) = response;
        assert_eq!(content, FAKE_BODY);
    }
}
