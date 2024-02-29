//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;

use crate::infra::{certs, dns};

pub trait LogSafeDisplay: Display {}

#[derive(displaydoc::Display, Debug, thiserror::Error)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum NetError {
    /// Failed to load certificates
    CertError,
    /// DNS lookup failed
    DnsError,
    /// Failed to establish TCP connection to any of the IPs
    TcpConnectionFailed,
    /// SSL error
    SslError,
    /// Failed to establish SSL connection
    SslFailedHandshake,
    /// `Content-Length` header value is invalid
    ContentLengthHeaderInvalid,
    /// Content stream is not consistent with the `Content-Length` header
    ContentLengthHeaderDoesntMatchDataSize,
    /// Failed to upgrade to H2
    Http2FailedHandshake,
    /// Operation timed out
    Timeout,
    /// Failure
    Failure,
    /// Failed to decode data received from the server
    IncomingDataInvalid,
    /// Request object must contain only ASCII text as header names and values.
    RequestHasInvalidHeader,
    /// Received a WebSocket frame of an unexpected type
    UnexpectedFrameReceived,
    /// Tried to use closed channel
    ChannelClosed,
    /// WebSocket error: {0}
    WebSocketError(#[from] crate::infra::ws::Error),
    /// Channel closed due to an error
    ChannelClosedWithError,
    /// Channel closed by remote peer
    ChannelClosedByRemotePeer,
    /// Channel closed by local peer
    ChannelClosedByLocalPeer,
    /// No incoming messages on the WebSocket channel
    ChannelIdle,
    /// Service is not connected
    NoServiceConnection,
    /// Request message from the server is missing the `id` field
    ServerRequestMissingId,
    /// Failed while sending a request from the server to the incoming  messages channel
    FailedToPassMessageToIncomingChannel,
    /// An HTTP stream was interrupted while receiving data.
    HttpInterruptedDuringReceive,
}

impl LogSafeDisplay for NetError {}

impl From<std::io::Error> for NetError {
    fn from(value: std::io::Error) -> Self {
        log::error!("{}", value);
        NetError::Failure
    }
}

impl From<certs::Error> for NetError {
    fn from(_value: certs::Error) -> Self {
        NetError::CertError
    }
}

impl From<dns::Error> for NetError {
    fn from(_value: dns::Error) -> Self {
        NetError::DnsError
    }
}

impl From<boring::error::ErrorStack> for NetError {
    fn from(_value: boring::error::ErrorStack) -> Self {
        NetError::SslError
    }
}

impl From<tungstenite::error::Error> for NetError {
    fn from(value: tungstenite::error::Error) -> Self {
        Self::WebSocketError(value.into())
    }
}
