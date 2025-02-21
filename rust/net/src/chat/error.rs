//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net_infra::errors::{LogSafeDisplay, TransportConnectError};
use libsignal_net_infra::extract_retry_after_seconds;
use libsignal_net_infra::route::ConnectError;
use libsignal_net_infra::timeouts::TimeoutOr;
use libsignal_net_infra::ws::{WebSocketConnectError, WebSocketServiceError};

use crate::ws::WebSocketServiceConnectError;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ChatServiceError {
    /// websocket error: {0}
    WebSocket(#[from] WebSocketServiceError),
    /// App version too old
    AppExpired,
    /// Device deregistered or delinked
    DeviceDeregistered,
    /// Unexpected text frame received
    UnexpectedFrameReceived,
    /// Request message from the server is missing the `id` field
    ServerRequestMissingId,
    /// Failed to decode data received from the server
    IncomingDataInvalid,
    /// Request object must contain only ASCII text as header names and values.
    RequestHasInvalidHeader,
    /// Timed out while establishing connection
    TimeoutEstablishingConnection,
    /// Timed out while sending a request
    RequestSendTimedOut,
    /// All connection routes failed or timed out
    AllConnectionRoutesFailed,
    /// Invalid connection configuration
    InvalidConnectionConfiguration,
    /// Connection is already closed
    Disconnected,
    /// Service is unavailable now, try again after {retry_after_seconds}s
    RetryLater { retry_after_seconds: u32 },
}

impl ChatServiceError {
    pub fn from_single_connect_error(
        e: TimeoutOr<ConnectError<WebSocketServiceConnectError>>,
    ) -> Self {
        use crate::infra::route::ConnectError;
        match e {
            TimeoutOr::Other(ConnectError::NoResolvedRoutes) => {
                ChatServiceError::InvalidConnectionConfiguration
            }
            TimeoutOr::Other(ConnectError::AllAttemptsFailed) => {
                ChatServiceError::AllConnectionRoutesFailed
            }
            TimeoutOr::Other(ConnectError::FatalConnect(err)) => err.into(),
            TimeoutOr::Timeout {
                attempt_duration: _,
            } => ChatServiceError::TimeoutEstablishingConnection,
        }
    }
}

impl LogSafeDisplay for ChatServiceError {}

impl From<WebSocketServiceConnectError> for ChatServiceError {
    fn from(e: WebSocketServiceConnectError) -> Self {
        match e {
            WebSocketServiceConnectError::Connect(e, _) => match e {
                WebSocketConnectError::Transport(e) => match e {
                    TransportConnectError::InvalidConfiguration => {
                        WebSocketServiceError::Other("invalid configuration")
                    }
                    TransportConnectError::TcpConnectionFailed => {
                        WebSocketServiceError::Other("TCP connection failed")
                    }
                    TransportConnectError::DnsError => WebSocketServiceError::Other("DNS error"),
                    TransportConnectError::SslError(_)
                    | TransportConnectError::SslFailedHandshake(_) => {
                        WebSocketServiceError::Other("TLS failure")
                    }
                    TransportConnectError::CertError => {
                        WebSocketServiceError::Other("failed to load certificates")
                    }
                    TransportConnectError::ProxyProtocol => {
                        WebSocketServiceError::Other("proxy protocol error")
                    }
                    TransportConnectError::ClientAbort => {
                        WebSocketServiceError::Other("client abort error")
                    }
                }
                .into(),
                WebSocketConnectError::Timeout => Self::TimeoutEstablishingConnection,
                WebSocketConnectError::WebSocketError(e) => Self::WebSocket(e.into()),
            },
            WebSocketServiceConnectError::RejectedByServer {
                response,
                received_at: _,
            } => {
                // Retry-After takes precedence over everything else.
                if let Some(retry_after_seconds) = extract_retry_after_seconds(response.headers()) {
                    return Self::RetryLater {
                        retry_after_seconds,
                    };
                }
                match response.status().as_u16() {
                    499 => Self::AppExpired,
                    403 => {
                        // Technically this only applies to identified sockets,
                        // but unidentified sockets should never produce a 403 anyway.
                        Self::DeviceDeregistered
                    }
                    _ => Self::WebSocket(WebSocketServiceError::Http(response)),
                }
            }
        }
    }
}
