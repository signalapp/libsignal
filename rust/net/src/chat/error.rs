//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net_infra::errors::{LogSafeDisplay, RetryLater, TransportConnectError};
use libsignal_net_infra::extract_retry_later;
use libsignal_net_infra::route::ConnectError as RouteConnectError;
use libsignal_net_infra::timeouts::TimeoutOr;
use libsignal_net_infra::ws::{WebSocketConnectError, WebSocketError};

use crate::ws::WebSocketServiceConnectError;

/// Error that can occur when sending a request to the Chat service.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SendError {
    /// timed out while sending a request
    RequestTimedOut,
    /// connection is already closed
    Disconnected,
    /// the server explicitly disconnected us because we connected elsewhere with the same credentials
    ConnectedElsewhere,
    /// the server explicitly disconnected us for some reason other than that we connected elsewhere
    ConnectionInvalidated,
    /// websocket error: {0}
    WebSocket(#[from] WebSocketError),
    /// failed to decode data received from the server
    IncomingDataInvalid,
    /// request object must contain only ASCII text as header names and values.
    RequestHasInvalidHeader,
}
impl LogSafeDisplay for SendError where WebSocketError: LogSafeDisplay {}

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
    /// {0}
    RetryLater(#[from] RetryLater),
    /// app version is too old
    AppExpired,
    /// device was deregistered
    DeviceDeregistered,
}
impl LogSafeDisplay for ConnectError {}

impl<T: Into<ConnectError>> From<TimeoutOr<RouteConnectError<T>>> for ConnectError {
    fn from(e: TimeoutOr<RouteConnectError<T>>) -> Self {
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
                if let Some(retry_after) = extract_retry_later(response.headers()) {
                    return Self::RetryLater(retry_after);
                }
                match response.status().as_u16() {
                    499 => Self::AppExpired,
                    403 => {
                        // Technically this only applies to identified sockets,
                        // but unidentified sockets should never produce a 403 anyway.
                        Self::DeviceDeregistered
                    }
                    _ => Self::WebSocket(WebSocketError::Http(response).into()),
                }
            }
        }
    }
}

/// This is consistent with the conversion from a WebSocketServiceConnectError that nested-ly
/// contains a TransportConnectError.
///
/// It's available so that preconnecting chat can return the same kind of error as fully connecting
/// chat. It's *not* provided on WebSocketConnectError beacuse that would skip the checking for
/// particular HTTP responses.
impl From<TransportConnectError> for ConnectError {
    fn from(e: TransportConnectError) -> Self {
        Self::WebSocket(WebSocketConnectError::Transport(e))
    }
}
