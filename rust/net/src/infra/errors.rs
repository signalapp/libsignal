//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use crate::infra::{certs, dns};
use std::fmt::Display;

pub trait LogSafeDisplay: Display {}

#[derive(displaydoc::Display, Debug, thiserror::Error)]
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
    /// Failed to upgrade HTTP connection to WebSockets
    WsFailedHandshake,
    /// Failed to upgrade to H2
    Http2FailedHandshake,
    /// Operation timed out
    Timeout,
    /// Failure
    Failure,
}

impl LogSafeDisplay for NetError {}

impl From<std::io::Error> for NetError {
    fn from(_value: std::io::Error) -> Self {
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
