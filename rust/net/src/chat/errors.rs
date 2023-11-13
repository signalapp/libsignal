//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::infra::errors::{LogSafeDisplay, NetError};

#[derive(displaydoc::Display, Debug)]
pub enum ChatNetworkError {
    /// Failed to decode data received from the server
    IncomingDataInvalid,
    /// Request object must contain only ASCII text as header names and values.
    RequestHasInvalidHeader,
    /// Failed to send message over WebSocket
    FailedToSendWebSocket(tungstenite::Error),
    /// Failed to send message over HTTP
    FailedToSendHttp(NetError),
    /// Failed to connect over HTTP
    FailedToConnectHttp(NetError),
    /// Failed to pass message to the writer task
    FailedToPassMessageToSenderTask,
    /// Response to a request was not received
    ResponseNotReceived,
    /// Received a WebSocket frame of an unexpected type
    UnexpectedFrameReceived,
    /// Request timed out
    Timeout,
    /// Tried to use closed channel
    ChannelClosed,
    /// WebSocket error
    WebSocketError(tungstenite::Error),
    /// Channel closed due to an error
    ChannelClosedWithError(hyper::Error),
    /// Channel closed by remote peer
    ChannelClosedByRemotePeer,
    /// Channel closed by local peer
    ChannelClosedByLocalPeer,
    /// No incoming messages on the WebSocket channel
    ChannelIdle,
    /// Service is not connected
    NoServiceConnection,
    /// Failed to establish WebSocket connection
    FailedToConnectWebSocket,
    /// Request message from the server is missing the `id` field
    ServerRequestMissingId,
    /// Failed while sending a request from the server to the incoming  messages channel
    FailedToPassMessageToIncomingChannel,
}

impl LogSafeDisplay for ChatNetworkError {}
