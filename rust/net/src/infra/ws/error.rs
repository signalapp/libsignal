//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! Errors that can be returned during websocket operations. The top-level
//! [`Error`] type is a mirror of [`tungstenite::error::Error`] whose
//! [`std::fmt::Display`] impl doesn't contain any user data.

use crate::infra::errors::LogSafeDisplay;

/// Mirror of [`tungstenite::error::Error`].
///
/// Provides a user-data-free [`std::fmt::Display`] implementation.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error, displaydoc::Display)]
pub enum Error {
    /// The connection is closed
    Closed,

    /// Reading or writing failed
    Io,

    /// Space: {0}
    Space(SpaceError),

    /// WebSocket protocol error: {0}
    Protocol(#[from] ProtocolError),

    /// Invalid URL
    Url,

    /// UTF-8 encoding error
    BadUtf8,

    /// The server sent a non-Ok HTTP status: {0}
    Http(http::StatusCode),

    /// Other HTTP error
    HttpFormat(#[from] HttpFormatError),

    /// TLS error; this should not happen since tungstinite's TLS is not used
    #[allow(clippy::enum_variant_names)]
    UnexpectedTlsError,
}

impl LogSafeDisplay for Error {}

/// Mirror of [`tungstenite::error::CapacityError`] and [`tungstenite::Error::SendQueueFull`].
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
pub struct ProtocolError(#[from] tungstenite::error::ProtocolError);

impl std::fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use tungstenite::error::ProtocolError;
        let str = match &self.0 {
            ProtocolError::InvalidHeader(header_name) => {
                return write!(f, "InvalidHeader: {header_name}")
            }

            ProtocolError::WrongHttpMethod => "WrongHttpMethod",
            ProtocolError::WrongHttpVersion => "WrongHttpVersion",
            ProtocolError::MissingConnectionUpgradeHeader => "MissingConnectionUpgradeHeader",
            ProtocolError::MissingUpgradeWebSocketHeader => "MissingUpgradeWebSocketHeader",
            ProtocolError::MissingSecWebSocketVersionHeader => "MissingSecWebSocketVersionHeader",
            ProtocolError::MissingSecWebSocketKey => "MissingSecWebSocketKey",
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

impl From<http::Error> for HttpFormatError {
    fn from(value: http::Error) -> Self {
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

impl From<tungstenite::Error> for Error {
    fn from(value: tungstenite::Error) -> Self {
        match value {
            tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => {
                Self::Closed
            }
            tungstenite::Error::Io(_) | tungstenite::Error::AttackAttempt => Self::Io,
            tungstenite::Error::Tls(_) => Self::UnexpectedTlsError,
            tungstenite::Error::Capacity(e) => Self::Space(SpaceError::from(e)),
            tungstenite::Error::Protocol(e) => Self::Protocol(ProtocolError::from(e)),
            tungstenite::Error::WriteBufferFull(_) => Self::Space(SpaceError::SendQueueFull),
            tungstenite::Error::Utf8 => Self::BadUtf8,
            tungstenite::Error::Url(_) => Self::Url,
            tungstenite::Error::Http(response) => Self::Http(response.status()),
            tungstenite::Error::HttpFormat(e) => Self::HttpFormat(HttpFormatError::from(e)),
        }
    }
}
