//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::fmt;

use prost::DecodeError;

use crate::proto::svr4;

#[derive(Debug, displaydoc::Display, PartialEq)]
pub enum Error {
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
#[derive(Debug, strum::Display, PartialEq)]
pub enum ErrorStatus {
    Unset,
    Missing,
    InvalidRequest,
    Error,
}

impl std::error::Error for Error {}

impl From<DecodeError> for Error {
    fn from(_err: DecodeError) -> Self {
        Self::BadData
    }
}
