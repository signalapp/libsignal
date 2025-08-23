//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;

use http::HeaderName;
use libsignal_net_infra::errors::{LogSafeDisplay, TransportConnectError};
use libsignal_net_infra::ws::{WebSocketConnectError, WebSocketError};
use tokio::time::Instant;

#[derive(Debug, thiserror::Error)]
pub enum WebSocketServiceConnectError {
    /// A special case of HTTP error where the response is considered to come
    /// from the Signal servers.
    ///
    /// See [`ConnectionParams::connection_confirmation_header`](crate::infra::ConnectionParams::connection_confirmation_header).
    RejectedByServer {
        response: Box<http::Response<Option<Vec<u8>>>>,
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
            WebSocketConnectError::WebSocketError(WebSocketError::Http(response))
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
                    libsignal_net_infra::ws::WebSocketError::Io(_),
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
                        libsignal_net_infra::ws::WebSocketError::Http(_)
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
                WebSocketConnectError::WebSocketError(
                    libsignal_net_infra::ws::WebSocketError::Http(Box::new(response_4xx.clone())),
                ),
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
