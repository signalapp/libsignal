//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;
use std::time::Duration;

use http::{HeaderName, HeaderValue};
use tokio_boring_signal::HandshakeError;

use crate::{AsStaticHttpHeader, certs};

pub trait LogSafeDisplay: Display {}

/// Vacuous implementation since you can't actually [`Display::fmt`] a
/// [`std::convert::Infallible`].
impl LogSafeDisplay for std::convert::Infallible {}

#[derive(Copy, Clone, Debug, thiserror::Error, displaydoc::Display)]
/// retry after {retry_after_seconds}s
pub struct RetryLater {
    pub retry_after_seconds: u32,
}

/// Errors that can occur during transport-level connection establishment.
#[derive(displaydoc::Display, Debug, thiserror::Error)]
pub enum TransportConnectError {
    /// Invalid configuration for this connection
    InvalidConfiguration,
    /// Failed to establish TCP connection to any of the IPs
    TcpConnectionFailed,
    /// SSL error: {0}
    SslError(SslErrorReasons),
    /// Failed to load certificates
    CertError,
    /// Failed to establish SSL connection: {0}
    SslFailedHandshake(FailedHandshakeReason),
    /// Proxy handshake failed
    ProxyProtocol,
    /// Abort due to local error
    ClientAbort,
}
impl LogSafeDisplay for TransportConnectError {}

#[derive(Debug)]
pub struct SslErrorReasons(boring_signal::error::ErrorStack);

impl Display for SslErrorReasons {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(
                self.0
                    .errors()
                    .iter()
                    .flat_map::<Option<&'static str>, _>(boring_signal::error::Error::reason),
            )
            .finish()
    }
}

#[derive(Debug, PartialEq)]
pub struct FailedHandshakeReason {
    io: Option<std::io::ErrorKind>,
    code: Option<boring_signal::ssl::ErrorCode>,
}

impl FailedHandshakeReason {
    pub const TIMED_OUT: Self = Self {
        io: Some(std::io::ErrorKind::TimedOut),
        code: None,
    };
}

/// Error type for TLS handshake timeouts
#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("TLS handshake timed out")]
pub struct TlsHandshakeTimeout;

impl<S> From<HandshakeError<S>> for FailedHandshakeReason {
    fn from(value: HandshakeError<S>) -> Self {
        log::debug!("handshake error: {value}");
        let io = value.as_io_error().map(std::io::Error::kind);
        let code = value.code();
        Self { io, code }
    }
}

impl LogSafeDisplay for FailedHandshakeReason {}
impl Display for FailedHandshakeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.io.is_none() && self.code.is_none() {
            return write!(f, "unknown error");
        }

        if let Some(code) = self.code {
            write!(f, "boring SSL error code:{}", code.as_raw())?;
        }

        if let Some(io) = self.io {
            write!(f, "IO error: {io}")?
        }

        Ok(())
    }
}

impl RetryLater {
    /// The amount of time to wait before retrying, as a [`Duration`].
    pub fn duration(&self) -> Duration {
        Duration::from_secs(self.retry_after_seconds.into())
    }
}

impl AsStaticHttpHeader for RetryLater {
    const HEADER_NAME: HeaderName = HeaderName::from_static("retry-after");

    fn header_value(&self) -> HeaderValue {
        HeaderValue::from(self.retry_after_seconds)
    }
}

impl From<boring_signal::error::ErrorStack> for TransportConnectError {
    fn from(value: boring_signal::error::ErrorStack) -> Self {
        Self::SslError(SslErrorReasons(value))
    }
}

impl From<certs::Error> for TransportConnectError {
    fn from(_value: certs::Error) -> Self {
        Self::CertError
    }
}

impl<S> From<HandshakeError<S>> for TransportConnectError {
    fn from(error: HandshakeError<S>) -> Self {
        Self::SslFailedHandshake(FailedHandshakeReason::from(error))
    }
}

impl From<TransportConnectError> for std::io::Error {
    fn from(value: TransportConnectError) -> Self {
        use std::io::ErrorKind;
        let kind = match value {
            TransportConnectError::InvalidConfiguration => ErrorKind::InvalidInput,
            TransportConnectError::TcpConnectionFailed => ErrorKind::ConnectionRefused,
            TransportConnectError::SslFailedHandshake(_)
            | TransportConnectError::SslError(_)
            | TransportConnectError::CertError
            | TransportConnectError::ProxyProtocol => ErrorKind::InvalidData,
            TransportConnectError::ClientAbort => ErrorKind::ConnectionAborted,
        };
        Self::new(kind, value.to_string())
    }
}

impl From<TlsHandshakeTimeout> for TransportConnectError {
    fn from(TlsHandshakeTimeout: TlsHandshakeTimeout) -> Self {
        Self::SslFailedHandshake(FailedHandshakeReason::TIMED_OUT)
    }
}
