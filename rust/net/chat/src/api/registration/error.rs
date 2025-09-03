//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use libsignal_net::infra::errors::LogSafeDisplay;

use crate::api::RequestError;
use crate::api::registration::{
    InvalidSessionId, RegistrationLock, VerificationCodeNotDeliverable,
};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum CreateSessionError {
    /// invalid session ID value
    InvalidSessionId,
}
impl LogSafeDisplay for CreateSessionError {}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum ResumeSessionError {
    /// invalid session ID value
    InvalidSessionId,
    /// session not found
    SessionNotFound,
}
impl LogSafeDisplay for ResumeSessionError {}

/// Error response to a request made on an established session.
///
/// This is notionally a precursor to one of [`UpdateSessionError`],
/// [`RequestVerificationCodeError`], and [`SubmitVerificationError`].
/// The [`From`] implementations attempt to extract more specific error
/// variants.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum SessionRequestError {
    /// unknown HTTP response status: {status}
    UnrecognizedStatus {
        status: StatusCode,
        response_headers: HeaderMap,
        response_body: Option<Bytes>,
    },
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum UpdateSessionError {
    /// the information provided was rejected
    Rejected,
}
impl LogSafeDisplay for UpdateSessionError {}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum RequestVerificationCodeError {
    /// invalid session ID value
    InvalidSessionId,
    /// session not found
    SessionNotFound,
    /// the session is already verified or not ready for a code request
    NotReadyForVerification,
    /// the request to send a verification code with the requested transport could not be fulfilled
    SendFailed,
    /// the code could not be delivered
    CodeNotDeliverable(VerificationCodeNotDeliverable),
}
impl LogSafeDisplay for RequestVerificationCodeError {}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum SubmitVerificationError {
    /// invalid session ID value
    InvalidSessionId,
    /// session not found
    SessionNotFound,
    /// the session is already verified or no code was requested
    NotReadyForVerification,
}
impl LogSafeDisplay for SubmitVerificationError {}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum CheckSvr2CredentialsError {
    /// provided list of SVR2 credentials could not be parsed.
    CredentialsCouldNotBeParsed,
}
impl LogSafeDisplay for CheckSvr2CredentialsError {}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum RegisterAccountError {
    /// a device transfer is possible and was not explicitly skipped.
    DeviceTransferIsPossibleButNotSkipped,
    /// registration recovery password verification failed
    RegistrationRecoveryVerificationFailed,
    /// registration lock is enabled
    RegistrationLock(RegistrationLock),
}
impl LogSafeDisplay for RegisterAccountError {}

impl<D> From<InvalidSessionId> for RequestError<CreateSessionError, D> {
    fn from(InvalidSessionId: InvalidSessionId) -> Self {
        Self::Other(CreateSessionError::InvalidSessionId)
    }
}

impl<D> From<InvalidSessionId> for RequestError<ResumeSessionError, D> {
    fn from(InvalidSessionId: InvalidSessionId) -> Self {
        Self::Other(ResumeSessionError::InvalidSessionId)
    }
}

impl<D> From<InvalidSessionId> for RequestError<UpdateSessionError, D> {
    fn from(InvalidSessionId: InvalidSessionId) -> Self {
        Self::Unexpected {
            log_safe: "invalid session ID in update session response".to_owned(),
        }
    }
}

impl<D> From<InvalidSessionId> for RequestError<RequestVerificationCodeError, D> {
    fn from(InvalidSessionId: InvalidSessionId) -> Self {
        Self::Other(RequestVerificationCodeError::InvalidSessionId)
    }
}

impl<D> From<InvalidSessionId> for RequestError<SubmitVerificationError, D> {
    fn from(InvalidSessionId: InvalidSessionId) -> Self {
        Self::Other(SubmitVerificationError::InvalidSessionId)
    }
}
