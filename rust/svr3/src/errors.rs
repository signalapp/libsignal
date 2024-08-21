//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::fmt;

pub use crate::oprf::errors::OPRFError;
pub use crate::ppss::PPSSError;
use crate::proto::svr4;
use prost::DecodeError;

#[derive(Debug, displaydoc::Display, PartialEq)]
pub enum Error {
    /// OPRF error: {0}
    Oprf(OPRFError),
    /// PPSS error: {0}, {1} tries remaining
    Ppss(PPSSError, u32),
    /// Invalid protobuf
    BadData,
    /// Unexpected or missing server response
    BadResponse,
    /// Response status is not OK: {0}
    BadResponseStatus(ErrorStatus),
    /// Inputs {got} do not match the correct number of servers {servers}
    NumServers { servers: usize, got: usize },
    /// No auth version was usable.
    NoUsableVersion,
    /// Response status for v4 protocol is not OK: {0}
    BadResponseStatus4(svr4::response4::Status),
    /// Restore failed, {0} tries remaining
    RestoreFailed(u32),
}

impl std::fmt::Display for svr4::response4::Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str_name())
    }
}

/// Represents an erroneous SVR3 response status
#[derive(Debug, strum_macros::Display, PartialEq)]
pub enum ErrorStatus {
    Unset,
    Missing,
    InvalidRequest,
    Error,
}

impl std::error::Error for Error {}

impl From<OPRFError> for Error {
    fn from(err: OPRFError) -> Self {
        Self::Oprf(err)
    }
}

impl From<DecodeError> for Error {
    fn from(_err: DecodeError) -> Self {
        Self::BadData
    }
}
