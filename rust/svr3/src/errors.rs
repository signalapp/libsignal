//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
pub use crate::oprf::errors::OPRFError;
pub use crate::ppss::PPSSError;
use prost::DecodeError;

#[derive(Debug, displaydoc::Display)]
pub enum Error {
    /// OPRF error: {0}
    Oprf(OPRFError),
    /// PPSS error: {0}
    Ppss(PPSSError),
    /// Invalid protobuf
    BadData,
    /// Unexpected or missing server response
    BadResponse,
    /// Response status is not OK: {0}
    BadResponseStatus(ErrorStatus),
}

/// Represents an erroneous SVR3 response status
#[derive(Debug, strum_macros::Display)]
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

impl From<PPSSError> for Error {
    fn from(err: PPSSError) -> Self {
        Self::Ppss(err)
    }
}

impl From<DecodeError> for Error {
    fn from(_err: DecodeError) -> Self {
        Self::BadData
    }
}
