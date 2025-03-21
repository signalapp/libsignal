//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use http::StatusCode;
use libsignal_net_infra::errors::{LogSafeDisplay, RetryLater};

use crate::registration::{InvalidSessionId, ResponseError};

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum RequestError<E> {
    /// the request timed out
    Timeout,
    /// unknown error: {0}
    Unknown(String),
    /// {0}
    Other(E),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum CreateSessionError {
    /// invalid session ID value
    InvalidSessionId,
    /// the request did not pass server validation
    RequestWasNotValid,
    /// {0}
    RetryLater(#[from] RetryLater),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub enum ResumeSessionError {
    /// invalid session ID value
    InvalidSessionId,
    /// session not found
    SessionNotFound,
    /// the server's response was invalid
    InvalidResponse,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub(super) enum SessionRequestError {
    /// {0}
    RetryLater(#[from] RetryLater),
    /// unknown HTTP response status: {0}
    UnrecognizedStatus(StatusCode),
}

impl From<RetryLater> for RequestError<ResumeSessionError> {
    fn from(value: RetryLater) -> Self {
        // The server doesn't return this code for GET requests.
        Self::Unknown(value.to_string())
    }
}

impl From<InvalidSessionId> for RequestError<ResumeSessionError> {
    fn from(InvalidSessionId: InvalidSessionId) -> Self {
        Self::Other(ResumeSessionError::InvalidSessionId)
    }
}

impl From<InvalidSessionId> for RequestError<CreateSessionError> {
    fn from(InvalidSessionId: InvalidSessionId) -> Self {
        Self::Other(CreateSessionError::InvalidSessionId)
    }
}

impl From<RetryLater> for RequestError<CreateSessionError> {
    fn from(value: RetryLater) -> Self {
        Self::Other(CreateSessionError::RetryLater(value))
    }
}

impl From<ResponseError> for RequestError<CreateSessionError> {
    fn from(value: ResponseError) -> Self {
        match value {
            ResponseError::RetryLater(retry_later) => RequestError::Other(retry_later.into()),
            error @ (ResponseError::UnexpectedContentType(_)
            | ResponseError::MissingBody
            | ResponseError::InvalidJson
            | ResponseError::UnexpectedData) => {
                RequestError::Unknown((&error as &dyn LogSafeDisplay).to_string())
            }
            ResponseError::UnrecognizedStatus(status_code) => match status_code {
                StatusCode::UNPROCESSABLE_ENTITY => {
                    RequestError::Other(CreateSessionError::RequestWasNotValid)
                }
                code => {
                    log::error!("got unexpected HTTP status {status_code} when creating a session");
                    RequestError::Unknown(format!("unexpected HTTP status {code}"))
                }
            },
        }
    }
}

impl From<ResponseError> for RequestError<ResumeSessionError> {
    fn from(value: ResponseError) -> Self {
        match value {
            ResponseError::RetryLater(retry_later) => retry_later.into(),
            error @ (ResponseError::UnexpectedContentType(_)
            | ResponseError::MissingBody
            | ResponseError::InvalidJson
            | ResponseError::UnexpectedData) => {
                RequestError::Unknown((&error as &dyn LogSafeDisplay).to_string())
            }
            ResponseError::UnrecognizedStatus(status_code) => match status_code {
                StatusCode::NOT_FOUND => RequestError::Other(ResumeSessionError::SessionNotFound),
                StatusCode::UNPROCESSABLE_ENTITY => {
                    RequestError::Other(ResumeSessionError::InvalidSessionId)
                }
                code => {
                    log::error!("got unexpected HTTP status {status_code} when reading a session");
                    RequestError::Unknown(format!("unexpected HTTP status {code}"))
                }
            },
        }
    }
}

impl From<RetryLater> for RequestError<SessionRequestError> {
    fn from(value: RetryLater) -> Self {
        Self::Other(value.into())
    }
}

impl From<ResponseError> for RequestError<SessionRequestError> {
    fn from(value: ResponseError) -> Self {
        match value {
            ResponseError::RetryLater(retry) => Self::Other(retry.into()),
            error @ (ResponseError::UnexpectedContentType(_)
            | ResponseError::MissingBody
            | ResponseError::InvalidJson
            | ResponseError::UnexpectedData) => {
                RequestError::Unknown((&error as &dyn LogSafeDisplay).to_string())
            }
            ResponseError::UnrecognizedStatus(status_code) => {
                Self::Other(SessionRequestError::UnrecognizedStatus(status_code))
            }
        }
    }
}

#[cfg(test)]
impl From<RetryLater> for RequestError<RetryLater> {
    fn from(value: RetryLater) -> Self {
        Self::Other(value)
    }
}
