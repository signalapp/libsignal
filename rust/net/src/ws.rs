//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;
use std::time::Duration;

use async_trait::async_trait;
use http::HeaderName;
use libsignal_net_infra::connection_manager::{ErrorClass, ErrorClassifier};
use libsignal_net_infra::errors::{LogSafeDisplay, TransportConnectError};
use libsignal_net_infra::service::{CancellationToken, ServiceConnector};
use libsignal_net_infra::ws::WebSocketConnectError;
use libsignal_net_infra::{extract_retry_after_seconds, ConnectionParams};
use tokio::time::Instant;

#[derive(Debug, thiserror::Error)]
pub enum WebSocketServiceConnectError {
    /// A special case of HTTP error where the response is considered to come
    /// from the Signal servers.
    ///
    /// See [`ConnectionParams::connection_confirmation_header`](crate::infra::ConnectionParams::connection_confirmation_header).
    RejectedByServer {
        response: http::Response<Option<Vec<u8>>>,
        received_at: Instant,
    },
    /// A connection error that wasn't caused by a server rejection.
    ///
    /// This variant can only be constructed by code in this module. Use
    /// [`WebSocketServiceConnectError::from_websocket_error`] to process a
    /// [`WebSocketConnectError`] and check for server-originating rejection.
    Connect(WebSocketConnectError, NotRejectedByServer),
}

impl WebSocketServiceConnectError {
    pub fn from_websocket_error(
        error: WebSocketConnectError,
        confirmation_header: Option<&HeaderName>,
        received_at: Instant,
    ) -> Self {
        match error {
            WebSocketConnectError::WebSocketError(tungstenite::Error::Http(response))
                if confirmation_header
                    .map(|header| response.headers().contains_key(header))
                    .unwrap_or(true) =>
            {
                // Promote any HTTP error to an explicit rejection if
                // - the confirmation header is present in the response, or
                // - there's no header to check
                Self::RejectedByServer {
                    response,
                    received_at,
                }
            }
            e => Self::Connect(
                e,
                NotRejectedByServer {
                    _limit_construction: (),
                },
            ),
        }
    }

    pub fn timeout() -> Self {
        Self::Connect(
            WebSocketConnectError::Timeout,
            NotRejectedByServer {
                _limit_construction: (),
            },
        )
    }

    pub fn invalid_proxy_configuration() -> Self {
        Self::Connect(
            WebSocketConnectError::Transport(TransportConnectError::InvalidConfiguration),
            NotRejectedByServer {
                _limit_construction: (),
            },
        )
    }
}

impl Display for WebSocketServiceConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebSocketServiceConnectError::RejectedByServer {
                response,
                received_at: _,
            } => {
                write!(
                    f,
                    "rejected by server with error code {}",
                    response.status()
                )
            }
            WebSocketServiceConnectError::Connect(
                web_socket_connect_error,
                _not_rejected_by_server,
            ) => web_socket_connect_error.fmt(f),
        }
    }
}

/// [`ServiceConnector`] wrapper that transforms the connect error using
/// [`WebSocketServiceConnectError::from_websocket_error`].
#[derive(Clone, Debug)]
pub struct WebSocketServiceConnector<S>(S);

impl<S> WebSocketServiceConnector<S> {
    pub fn new(inner: S) -> Self {
        Self(inner)
    }
}

#[async_trait]
impl<S: ServiceConnector<ConnectError: Into<WebSocketConnectError>> + Sync> ServiceConnector
    for WebSocketServiceConnector<S>
{
    type Service = S::Service;

    type Channel = S::Channel;

    type ConnectError = WebSocketServiceConnectError;

    async fn connect_channel(
        &self,
        connection_params: &ConnectionParams,
    ) -> Result<Self::Channel, Self::ConnectError> {
        self.0
            .connect_channel(connection_params)
            .await
            .map_err(|e| {
                // Because of the `await`, it's possible some time has already
                // elapsed since the response came in, but this is the first
                // chance we have to process it. A late timestamp means a more
                // conservative retry period, that's all.
                WebSocketServiceConnectError::from_websocket_error(
                    e.into(),
                    connection_params.connection_confirmation_header.as_ref(),
                    Instant::now(),
                )
            })
    }

    fn start_service(&self, channel: Self::Channel) -> (Self::Service, CancellationToken) {
        self.0.start_service(channel)
    }
}

/// Marker that indicates an error was not a rejection from a Signal server
///
/// This type is intentionally only constructible by code in this module. To
/// produce a [`WebSocketServiceConnectError::Connect`], call
/// [`WebSocketServiceConnectError::from_websocket_error`], which can construct
/// an instance of this type.
#[derive(Debug)]
pub struct NotRejectedByServer {
    _limit_construction: (),
}

impl LogSafeDisplay for WebSocketServiceConnectError {}

impl ErrorClassifier for WebSocketServiceConnectError {
    fn classify(&self) -> ErrorClass {
        let WebSocketServiceConnectError::RejectedByServer {
            response,
            received_at,
        } = self
        else {
            // If we didn't make it to the server, we should retry.
            return ErrorClass::Intermittent;
        };

        // Retry-After takes precedence over everything else.
        if let Some(retry_after_seconds) = extract_retry_after_seconds(response.headers()) {
            return ErrorClass::RetryAt(
                *received_at + Duration::from_secs(retry_after_seconds.into()),
            );
        }

        // If we're rejected based on the request (4xx), there's no point in retrying.
        if response.status().is_client_error() {
            return ErrorClass::Fatal;
        }

        // Otherwise, assume we have a server problem (5xx), and retry.
        ErrorClass::Intermittent
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use http::HeaderName;
    use test_case::test_matrix;
    use tokio::time::Instant;

    use super::*;

    #[test_matrix([None, Some("x-pinky-promise")])]
    fn classify_errors(confirmation_header: Option<&'static str>) {
        let now = Instant::now();
        let confirmation_header = confirmation_header.map(HeaderName::from_static);

        let non_http_error = WebSocketServiceConnectError::from_websocket_error(
            tungstenite::Error::Io(std::io::ErrorKind::BrokenPipe.into()).into(),
            confirmation_header.as_ref(),
            now,
        );
        assert_matches!(
            non_http_error,
            WebSocketServiceConnectError::Connect(
                libsignal_net_infra::ws::WebSocketConnectError::WebSocketError(
                    tungstenite::Error::Io(_),
                ),
                _
            )
        );

        let mut response_4xx = http::Response::new(None);
        *response_4xx.status_mut() = http::StatusCode::BAD_REQUEST;

        let http_4xx_error = WebSocketServiceConnectError::from_websocket_error(
            tungstenite::Error::Http(response_4xx.clone()).into(),
            confirmation_header.as_ref(),
            now,
        );
        if confirmation_header.is_some() {
            assert_matches!(
                http_4xx_error,
                WebSocketServiceConnectError::Connect(
                    libsignal_net_infra::ws::WebSocketConnectError::WebSocketError(
                        tungstenite::Error::Http(_)
                    ),
                    _
                )
            );
        } else {
            assert_matches!(
                http_4xx_error,
                WebSocketServiceConnectError::RejectedByServer { response: _, received_at } if received_at == now
            );
        }

        if let Some(header) = &confirmation_header {
            response_4xx
                .headers_mut()
                .append(header, http::HeaderValue::from_static("1"));

            let error_with_header = WebSocketServiceConnectError::from_websocket_error(
                WebSocketConnectError::WebSocketError(tungstenite::Error::Http(
                    response_4xx.clone(),
                )),
                confirmation_header.as_ref(),
                now,
            );
            assert_matches!(
                error_with_header,
                WebSocketServiceConnectError::RejectedByServer { response: _, received_at } if received_at == now
            );
        }
    }
}
