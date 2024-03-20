//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use http::header::ToStrError;

use crate::infra::errors::LogSafeDisplay;
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
    /// Service is not connected
    NoServiceConnection,
}

impl LogSafeDisplay for ChatServiceError {}

impl From<ToStrError> for ChatServiceError {
    fn from(_: ToStrError) -> Self {
        ChatServiceError::RequestHasInvalidHeader
    }
}
