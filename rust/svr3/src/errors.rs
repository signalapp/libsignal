use prost::DecodeError;
//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
pub use crate::oprf::errors::OPRFError;
pub use crate::ppss::PPSSError;

#[derive(Debug, displaydoc::Display)]
pub enum Error {
    /// OPRF error {0}
    Oprf(OPRFError),
    /// PPSS error {0}
    Ppss(PPSSError),
    /// Protocol error {0}
    Protocol(String),
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
        Self::Protocol("Malformed protobuf".to_string())
    }
}
