//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::fmt::Display;

use crate::infra::certs;

pub trait LogSafeDisplay: Display {}

/// Errors that can occur during transport-level connection establishment.
#[derive(displaydoc::Display, Debug, thiserror::Error)]
#[cfg_attr(test, derive(Eq, PartialEq))]
pub enum TransportConnectError {
    /// Failed to establish TCP connection to any of the IPs
    TcpConnectionFailed,
    /// DNS lookup failed
    DnsError,
    /// SSL error
    SslError,
    /// Failed to load certificates
    CertError,
    /// Failed to establish SSL connection
    SslFailedHandshake,
}

impl From<boring::error::ErrorStack> for TransportConnectError {
    fn from(_value: boring::error::ErrorStack) -> Self {
        Self::SslError
    }
}

impl From<certs::Error> for TransportConnectError {
    fn from(_value: certs::Error) -> Self {
        Self::CertError
    }
}

impl From<TransportConnectError> for std::io::Error {
    fn from(value: TransportConnectError) -> Self {
        use std::io::ErrorKind;
        let kind = match value {
            TransportConnectError::TcpConnectionFailed => ErrorKind::ConnectionRefused,
            TransportConnectError::SslFailedHandshake
            | TransportConnectError::SslError
            | TransportConnectError::CertError => ErrorKind::InvalidData,
            TransportConnectError::DnsError => ErrorKind::NotFound,
        };
        Self::new(kind, value.to_string())
    }
}
