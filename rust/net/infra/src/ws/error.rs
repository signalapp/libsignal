//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Errors that can be returned during websocket operations. Many types are mirrors of tungstenite
//! errors whose [`std::fmt::Display`] impl doesn't contain any user data.

use std::borrow::Borrow;

use tungstenite::protocol::CloseFrame;

use crate::errors::{LogSafeDisplay, TransportConnectError};

/// Errors that can occur when connecting a websocket.
#[derive(Debug, thiserror::Error)]
pub enum WebSocketConnectError {
    Transport(#[from] TransportConnectError),
    WebSocketError(#[from] super::WebSocketError),
}

impl std::fmt::Display for WebSocketConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebSocketConnectError::Transport(e) => write!(f, "transport: {e}"),
            WebSocketConnectError::WebSocketError(e) => {
                write!(f, "websocket error: {}", e)
            }
        }
    }
}

impl LogSafeDisplay for WebSocketConnectError {}

impl From<std::io::Error> for WebSocketConnectError {
    fn from(value: std::io::Error) -> Self {
        super::WebSocketError::Io(value).into()
    }
}

impl From<tungstenite::Error> for WebSocketConnectError {
    fn from(value: tungstenite::Error) -> Self {
        Self::WebSocketError(value.into())
    }
}

/// The connection was unexpectedly closed.
///
/// If a [`CloseFrame`] was sent, it is included.
#[derive(Debug)]
pub struct UnexpectedCloseError(Option<CloseFrame>);

impl std::fmt::Display for UnexpectedCloseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("unexpected close: ")?;
        match &self.0 {
            Some(close) => write!(f, "{close}"),
            None => f.write_str("[no close frame]"),
        }
    }
}

impl LogSafeDisplay for UnexpectedCloseError {}

impl From<Option<CloseFrame>> for UnexpectedCloseError {
    fn from(value: Option<CloseFrame>) -> Self {
        Self(value)
    }
}

/// Mirror of [`tungstenite::error::CapacityError`] and [`tungstenite::Error::WriteBufferFull`].
///
/// Provides a user-data-free [`std::fmt::Display`] implementation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error, displaydoc::Display)]
pub enum SpaceError {
    /// {0}
    Capacity(#[from] tungstenite::error::CapacityError),
    /// Send queue full
    SendQueueFull,
}

/// Mirror of [`tungstenite::error::ProtocolError`].
///
/// Provides a user-data-free [`std::fmt::Display`] implementation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub struct ProtocolError(#[from] pub(crate) tungstenite::error::ProtocolError);

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use tungstenite::error::{ProtocolError, SubProtocolError};
        let str = match &self.0 {
            ProtocolError::InvalidHeader(header_name) => {
                return write!(f, "InvalidHeader: {header_name}");
            }

            ProtocolError::WrongHttpMethod => "WrongHttpMethod",
            ProtocolError::WrongHttpVersion => "WrongHttpVersion",
            ProtocolError::MissingConnectionUpgradeHeader => "MissingConnectionUpgradeHeader",
            ProtocolError::MissingUpgradeWebSocketHeader => "MissingUpgradeWebSocketHeader",
            ProtocolError::MissingSecWebSocketVersionHeader => "MissingSecWebSocketVersionHeader",
            ProtocolError::MissingSecWebSocketKey => "MissingSecWebSocketKey",
            ProtocolError::SecWebSocketSubProtocolError(SubProtocolError::InvalidSubProtocol) => {
                "InvalidSubProtocol"
            }
            ProtocolError::SecWebSocketSubProtocolError(SubProtocolError::NoSubProtocol) => {
                "NoSubProtocol"
            }
            ProtocolError::SecWebSocketSubProtocolError(
                SubProtocolError::ServerSentSubProtocolNoneRequested,
            ) => "ServerSentSubProtocolNoneRequested",
            ProtocolError::SecWebSocketAcceptKeyMismatch => "SecWebSocketAcceptKeyMismatch",
            ProtocolError::JunkAfterRequest => "JunkAfterRequest",
            ProtocolError::CustomResponseSuccessful => "CustomResponseSuccessful",
            ProtocolError::HandshakeIncomplete => "HandshakeIncomplete",
            ProtocolError::HttparseError(_) => "HttparseError",
            ProtocolError::SendAfterClosing => "SendAfterClosing",
            ProtocolError::ReceivedAfterClosing => "ReceivedAfterClosing",
            ProtocolError::NonZeroReservedBits => "NonZeroReservedBits",
            ProtocolError::UnmaskedFrameFromClient => "UnmaskedFrameFromClient",
            ProtocolError::MaskedFrameFromServer => "MaskedFrameFromServer",
            ProtocolError::FragmentedControlFrame => "FragmentedControlFrame",
            ProtocolError::ControlFrameTooBig => "ControlFrameTooBig",
            ProtocolError::UnknownControlFrameType(_) => "UnknownControlFrameType",
            ProtocolError::UnknownDataFrameType(_) => "UnknownDataFrameType",
            ProtocolError::UnexpectedContinueFrame => "UnexpectedContinueFrame",
            ProtocolError::ExpectedFragment(_) => "ExpectedFragment",
            ProtocolError::ResetWithoutClosingHandshake => "ResetWithoutClosingHandshake",
            ProtocolError::InvalidOpcode(_) => "InvalidOpcode",
            ProtocolError::InvalidCloseSequence => "InvalidCloseSequence",
        };
        write!(f, "{str}")
    }
}

/// Mirror of [`http::Error`].
///
/// Provides a user-data-free [`std::fmt::Display`] implementation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HttpFormatError {
    StatusCode,
    Method,
    Uri,
    UriParts,
    HeaderName,
    HeaderValue,
    Unknown,
}

impl std::fmt::Display for HttpFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl<E: Borrow<http::Error>> From<E> for HttpFormatError {
    fn from(value: E) -> Self {
        let value = value.borrow();
        // Try to figure out the actual error type since there's no enum to
        // exhaustively match on.
        if value.is::<http::status::InvalidStatusCode>() {
            Self::StatusCode
        } else if value.is::<http::method::InvalidMethod>() {
            Self::Method
        } else if value.is::<http::uri::InvalidUri>() {
            Self::Uri
        } else if value.is::<http::uri::InvalidUriParts>() {
            Self::UriParts
        } else if value.is::<http::header::InvalidHeaderName>() {
            Self::HeaderName
        } else if value.is::<http::header::InvalidHeaderValue>() {
            Self::HeaderValue
        } else {
            Self::Unknown
        }
    }
}
