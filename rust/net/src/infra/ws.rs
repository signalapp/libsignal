//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::infra::errors::NetError;
use crate::infra::{connect_ssl, ConnectionParams};
use tokio_tungstenite as tt;
use tungstenite::handshake::client::generate_key;
use tungstenite::http;
use tungstenite::protocol::WebSocketConfig;

pub type WebSocketStream = tt::WebSocketStream<tokio_boring::SslStream<tokio::net::TcpStream>>;

const WS_ALPN: &[u8] = b"\x08http/1.1";

pub(crate) async fn connect_websocket(
    connection_params: &ConnectionParams,
    endpoint: &str,
    ws_config: WebSocketConfig,
) -> Result<WebSocketStream, NetError> {
    let ssl_stream = connect_ssl(connection_params, WS_ALPN).await?;
    // we need to explicitly create upgrade request
    // because request decorators require a request `Builder`
    let request_builder = http::Request::builder()
        .method("GET")
        .header(
            http::header::HOST,
            http::HeaderValue::from_str(&connection_params.host)
                .expect("valid `HOST` header value"),
        )
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", generate_key())
        .uri(format!(
            "wss://{}:{}{}",
            connection_params.host, connection_params.port, endpoint
        ));

    let request_builder = connection_params
        .http_request_decorator
        .decorate_request(request_builder);

    let (ws_stream, _response) = tokio_tungstenite::client_async_with_config(
        request_builder.body(()).expect("can get request body"),
        ssl_stream,
        Some(ws_config),
    )
    .await
    .map_err(|_| NetError::WsFailedHandshake)?;

    Ok(ws_stream)
}
