//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net_infra::errors::LogSafeDisplay;
use libsignal_net_infra::extract_retry_after_seconds;
use libsignal_net_infra::route::ConnectError as RouteConnectError;
use libsignal_net_infra::timeouts::TimeoutOr;
use libsignal_net_infra::ws::{WebSocketConnectError, WebSocketServiceError};

use crate::ws::WebSocketServiceConnectError;

/// Error that can occur when sending a request to the Chat service.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SendError {
    /// timed out while sending a request
    RequestTimedOut,
    /// connection is already closed
    Disconnected,
    /// websocket error: {0}
    WebSocket(#[from] WebSocketServiceError),
    /// failed to decode data received from the server
    IncomingDataInvalid,
    /// request object must contain only ASCII text as header names and values.
    RequestHasInvalidHeader,
}

/// Error that can occur when connecting to the Chat service.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ConnectError {
    /// timed out while establishing a connection
    Timeout,
    /// all connect attempts failed
    AllAttemptsFailed,
    /// the connection information was invalid
    InvalidConnectionConfiguration,
    /// websocket error: {0}
    WebSocket(#[from] WebSocketConnectError),
    /// retry after {retry_after_seconds}s
    RetryLater { retry_after_seconds: u32 },
    /// app version is too old
    AppExpired,
    /// device was deregistered
    DeviceDeregistered,
}
impl LogSafeDisplay for ConnectError {}

impl From<TimeoutOr<RouteConnectError<WebSocketServiceConnectError>>> for ConnectError {
    fn from(e: TimeoutOr<RouteConnectError<WebSocketServiceConnectError>>) -> Self {
        match e {
            TimeoutOr::Other(RouteConnectError::NoResolvedRoutes) => {
                ConnectError::InvalidConnectionConfiguration
            }
            TimeoutOr::Other(RouteConnectError::AllAttemptsFailed) => {
                ConnectError::AllAttemptsFailed
            }
            TimeoutOr::Other(RouteConnectError::FatalConnect(err)) => err.into(),
            TimeoutOr::Timeout {
                attempt_duration: _,
            } => ConnectError::Timeout,
        }
    }
}

impl From<WebSocketServiceConnectError> for ConnectError {
    fn from(e: WebSocketServiceConnectError) -> Self {
        match e {
            WebSocketServiceConnectError::Connect(e, _) => Self::WebSocket(e),
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
                    _ => Self::WebSocket(WebSocketConnectError::WebSocketError(
                        tungstenite::Error::Http(response),
                    )),
                }
            }
        }
    }
}
