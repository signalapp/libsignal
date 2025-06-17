//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use bytes::Bytes;
use http::{HeaderMap, StatusCode};
use libsignal_net::infra::errors::{LogSafeDisplay, RetryLater};

use crate::api::registration::{
    InvalidSessionId, RegistrationLock, VerificationCodeNotDeliverable,
};

#[derive(Debug, thiserror::Error, displaydoc::Display, strum::EnumString)]
pub enum RequestError<E> {
    /// the request timed out
    Timeout,
    /// the request did not pass server validation
    RequestWasNotValid,
    /// unknown error: {0}
    Unknown(String),
    /// {0}
    #[strum(disabled)]
    Other(E),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum CreateSessionError {
    /// invalid session ID value
    InvalidSessionId,
    /// {0}
    RetryLater(#[from] RetryLater),
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
    /// {0}
    RetryLater(#[from] RetryLater),
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
    /// {0}
    RetryLater(#[from] RetryLater),
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
    /// {0}
    RetryLater(#[from] RetryLater),
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
    /// {0}
    RetryLater(#[from] RetryLater),
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
    /// {0}
    RetryLater(#[from] RetryLater),
    /// registration recovery password verification failed
    RegistrationRecoveryVerificationFailed,
    /// registration lock is enabled
    RegistrationLock(RegistrationLock),
}
impl LogSafeDisplay for RegisterAccountError {}

/// Convert [`RequestError<SessionRequestError>`] into a typed version.
///
/// This boilerplate implementation delegates conversion to the specific
/// `From<SessionRequestError>` impls for `Self` to produce a `RequestError<E>`.
impl<E> From<RequestError<SessionRequestError>> for RequestError<E>
where
    SessionRequestError: Into<Self>,
{
    fn from(value: RequestError<SessionRequestError>) -> Self {
        match value {
            RequestError::Other(e) => e.into(),
            RequestError::Timeout => RequestError::Timeout,
            RequestError::RequestWasNotValid => RequestError::RequestWasNotValid,
            RequestError::Unknown(message) => RequestError::Unknown(message),
        }
    }
}

impl From<InvalidSessionId> for RequestError<CreateSessionError> {
    fn from(InvalidSessionId: InvalidSessionId) -> Self {
        Self::Other(CreateSessionError::InvalidSessionId)
    }
}

impl From<InvalidSessionId> for RequestError<ResumeSessionError> {
    fn from(InvalidSessionId: InvalidSessionId) -> Self {
        Self::Other(ResumeSessionError::InvalidSessionId)
    }
}

impl From<RetryLater> for RequestError<ResumeSessionError> {
    fn from(value: RetryLater) -> Self {
        // The server doesn't return this code for GET requests.
        Self::Unknown(value.to_string())
    }
}

impl From<RetryLater> for RequestError<CreateSessionError> {
    fn from(value: RetryLater) -> Self {
        Self::Other(CreateSessionError::RetryLater(value))
    }
}

impl From<RetryLater> for RequestError<SessionRequestError> {
    fn from(value: RetryLater) -> Self {
        Self::Other(value.into())
    }
}
