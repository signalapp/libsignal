//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::fmt;

use crate::proto::svrb;

#[derive(Debug, displaydoc::Display, PartialEq)]
pub enum Error {
    /// Invalid protobuf
    BadData,
    /// Unexpected or missing server response
    BadResponse,
    /// Inputs {got} do not match the correct number of servers {servers}
    NumServers { servers: usize, got: usize },
    /// No auth version was usable.
    NoUsableVersion,
    /// Response status for v4 protocol is not OK: {0}
    BadResponseStatus4(svrb::response4::Status),
    /// Restore failed, {0} tries remaining
    RestoreFailed(u32),
}

impl std::fmt::Display for svrb::response4::Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {}
