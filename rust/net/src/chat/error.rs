//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::infra::errors::LogSafeDisplay;
use crate::infra::reconnect;
use crate::infra::ws::WebSocketServiceError;

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ChatServiceError {
    /// websocket error: {0}
    WebSocket(#[from] WebSocketServiceError),
    /// Unexpected text frame received
    UnexpectedFrameReceived,
    /// Request message from the server is missing the `id` field
    ServerRequestMissingId,
    /// Failed while sending a request from the server to the incoming  messages channel
    FailedToPassMessageToIncomingChannel,
    /// Failed to decode data received from the server
    IncomingDataInvalid,
    /// Request object must contain only ASCII text as header names and values.
    RequestHasInvalidHeader,
    /// Timeout
    Timeout,
    /// Timed out while establishing connection after {attempts} attempts
    TimeoutEstablishingConnection { attempts: u16 },
    /// All connection routes failed or timed out, {attempts} attempts made
    AllConnectionRoutesFailed { attempts: u16 },
    /// Service is inactive
    ServiceInactive,
    /// Service is unavailable due to the lost connection
    ServiceUnavailable,
}

impl LogSafeDisplay for ChatServiceError {}

impl From<reconnect::ReconnectError> for ChatServiceError {
    fn from(e: reconnect::ReconnectError) -> Self {
        match e {
            reconnect::ReconnectError::Timeout { attempts } => {
                Self::TimeoutEstablishingConnection { attempts }
            }
            reconnect::ReconnectError::AllRoutesFailed { attempts } => {
                Self::AllConnectionRoutesFailed { attempts }
            }
            reconnect::ReconnectError::Inactive => Self::ServiceInactive,
        }
    }
}

impl From<reconnect::StateError> for ChatServiceError {
    fn from(e: reconnect::StateError) -> Self {
        match e {
            reconnect::StateError::Inactive => Self::ServiceInactive,
            reconnect::StateError::ServiceUnavailable => Self::ServiceUnavailable,
        }
    }
}
