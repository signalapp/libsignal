//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;

use tokio_boring_signal::HandshakeError;

use crate::certs;

pub trait LogSafeDisplay: Display {}

/// Vacuous implementation since you can't actually [`Display::fmt`] a
/// [`std::convert::Infallible`].
impl LogSafeDisplay for std::convert::Infallible {}

/// Errors that can occur during transport-level connection establishment.
#[derive(displaydoc::Display, Debug, thiserror::Error)]
pub enum TransportConnectError {
    /// Invalid configuration for this connection
    InvalidConfiguration,
    /// Failed to establish TCP connection to any of the IPs
    TcpConnectionFailed,
    /// DNS lookup failed
    DnsError,
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

#[derive(Debug)]
pub struct FailedHandshakeReason {
    io: Option<std::io::ErrorKind>,
    code: Option<boring_signal::ssl::ErrorCode>,
}

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
            TransportConnectError::DnsError => ErrorKind::NotFound,
            TransportConnectError::ClientAbort => ErrorKind::ConnectionAborted,
        };
        Self::new(kind, value.to_string())
    }
}
