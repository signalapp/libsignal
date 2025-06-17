//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net::infra::errors::LogSafeDisplay;

pub use crate::api::registration::*;
use crate::api::registration::{RegistrationLock, VerificationCodeNotDeliverable};
use crate::ws::registration::ResponseError;

impl From<ResponseError> for RequestError<ResumeSessionError> {
    fn from(value: ResponseError) -> Self {
        RequestError::<SessionRequestError>::from(value).into()
    }
}

impl From<ResponseError> for RequestError<CreateSessionError> {
    fn from(value: ResponseError) -> Self {
        RequestError::<SessionRequestError>::from(value).into()
    }
}

impl From<ResponseError> for RequestError<SessionRequestError> {
    fn from(value: ResponseError) -> Self {
        match value {
            ResponseError::InvalidRequest => Self::RequestWasNotValid,
            ResponseError::RetryLater(retry) => Self::Other(retry.into()),
            error @ (ResponseError::UnexpectedContentType(_)
            | ResponseError::MissingBody
            | ResponseError::InvalidJson
            | ResponseError::UnexpectedData) => {
                RequestError::Unknown((&error as &dyn LogSafeDisplay).to_string())
            }
            ResponseError::UnrecognizedStatus {
                status,
                response_headers,
                response_body,
            } => Self::Other(SessionRequestError::UnrecognizedStatus {
                status,
                response_headers,
                response_body,
            }),
        }
    }
}

impl From<SessionRequestError> for RequestError<CreateSessionError> {
    fn from(value: SessionRequestError) -> Self {
        match value {
            SessionRequestError::RetryLater(retry_later) => RequestError::Other(retry_later.into()),
            SessionRequestError::UnrecognizedStatus { status, .. } => {
                log::error!("got unexpected HTTP status {status} when creating a session");
                RequestError::Unknown(format!("unexpected HTTP status {status}"))
            }
        }
    }
}

impl From<SessionRequestError> for RequestError<ResumeSessionError> {
    fn from(value: SessionRequestError) -> Self {
        match value {
            SessionRequestError::RetryLater(retry_later) => retry_later.into(),
            SessionRequestError::UnrecognizedStatus { status, .. } => match status.as_u16() {
                404 => RequestError::Other(ResumeSessionError::SessionNotFound),
                400 => RequestError::Other(ResumeSessionError::InvalidSessionId),
                code => {
                    log::error!("got unexpected HTTP status {status} when reading a session");
                    RequestError::Unknown(format!("unexpected HTTP status {code}"))
                }
            },
        }
    }
}

impl From<SessionRequestError> for RequestError<UpdateSessionError> {
    fn from(value: SessionRequestError) -> Self {
        match value {
            SessionRequestError::RetryLater(retry_later) => RequestError::Other(retry_later.into()),
            SessionRequestError::UnrecognizedStatus { status, .. } => match status.as_u16() {
                403 => RequestError::Other(UpdateSessionError::Rejected),
                code => {
                    log::error!("got unexpected HTTP response status updating the session: {code}");
                    RequestError::Unknown(format!("unexpected HTTP status {code}"))
                }
            },
        }
    }
}

impl From<SessionRequestError> for RequestError<RequestVerificationCodeError> {
    fn from(value: SessionRequestError) -> Self {
        RequestError::Other(match value {
            SessionRequestError::RetryLater(retry_later) => retry_later.into(),
            SessionRequestError::UnrecognizedStatus {
                status,
                response_headers,
                response_body,
            } => match status.as_u16() {
                400 => RequestVerificationCodeError::InvalidSessionId,
                404 => RequestVerificationCodeError::SessionNotFound,
                409 => RequestVerificationCodeError::NotReadyForVerification,
                418 => RequestVerificationCodeError::SendFailed,
                440 => {
                    let Some(not_deliverable) = response_body.as_deref().and_then(|body| {
                        VerificationCodeNotDeliverable::from_response(&response_headers, body)
                    }) else {
                        return RequestError::Unknown("unexpected 440 response format".to_owned());
                    };
                    RequestVerificationCodeError::CodeNotDeliverable(not_deliverable)
                }
                _ => return RequestError::Unknown(format!("unexpected HTTP status {status}")),
            },
        })
    }
}

impl From<SessionRequestError> for RequestError<SubmitVerificationError> {
    fn from(value: SessionRequestError) -> Self {
        RequestError::Other(match value {
            SessionRequestError::RetryLater(retry_later) => retry_later.into(),
            SessionRequestError::UnrecognizedStatus { status, .. } => match status.as_u16() {
                400 => SubmitVerificationError::InvalidSessionId,
                404 => SubmitVerificationError::SessionNotFound,
                409 => SubmitVerificationError::NotReadyForVerification,
                _ => return RequestError::Unknown(format!("unexpected HTTP status {status}")),
            },
        })
    }
}

impl From<SessionRequestError> for RequestError<CheckSvr2CredentialsError> {
    fn from(value: SessionRequestError) -> Self {
        match value {
            SessionRequestError::RetryLater(retry_later) => {
                RequestError::Unknown(format!("unexpected {retry_later}"))
            }
            SessionRequestError::UnrecognizedStatus { status, .. } => match status.as_u16() {
                400 => RequestError::RequestWasNotValid,
                422 => RequestError::Other(CheckSvr2CredentialsError::CredentialsCouldNotBeParsed),
                _ => RequestError::Unknown(format!("unexpected status {status}")),
            },
        }
    }
}

impl From<SessionRequestError> for RequestError<RegisterAccountError> {
    fn from(value: SessionRequestError) -> Self {
        RequestError::Other(match value {
            SessionRequestError::RetryLater(retry_later) => retry_later.into(),
            SessionRequestError::UnrecognizedStatus {
                status,
                response_headers,
                response_body,
            } => match status.as_u16() {
                403 => RegisterAccountError::RegistrationRecoveryVerificationFailed,
                409 => RegisterAccountError::DeviceTransferIsPossibleButNotSkipped,
                423 => {
                    let Some(registration_lock) = response_body
                        .as_deref()
                        .and_then(|body| RegistrationLock::from_response(&response_headers, body))
                    else {
                        return RequestError::Unknown("unexpected 423 response format".to_owned());
                    };
                    RegisterAccountError::RegistrationLock(registration_lock)
                }
                _ => return RequestError::Unknown(format!("unexpected HTTP status {status}")),
            },
        })
    }
}

#[cfg(test)]
mod test {
    use std::fmt::Debug;

    use http::{HeaderMap, StatusCode};
    use itertools::Itertools;
    use libsignal_net::infra::errors::RetryLater;
    use strum::{IntoDiscriminant, IntoEnumIterator};
    use test_case::test_case;

    use super::*;
    use crate::ws::registration::CONTENT_TYPE_JSON;

    impl From<RetryLater> for RequestError<RetryLater> {
        fn from(value: RetryLater) -> Self {
            Self::Other(value)
        }
    }

    trait AsStatus {
        fn as_status(&self) -> Option<u16>;
    }

    trait CollectSortedStatuses {
        /// Returns the status code for each variant, sorted by value.
        fn sorted_statuses() -> Vec<u16>;
    }

    impl<T> CollectSortedStatuses for T
    where
        T: IntoDiscriminant<Discriminant: IntoEnumIterator + AsStatus>,
    {
        fn sorted_statuses() -> Vec<u16> {
            <T::Discriminant as IntoEnumIterator>::iter()
                .map(RequestError::Other)
                .chain([RequestError::RequestWasNotValid])
                .filter_map(|t| RequestError::<T::Discriminant>::as_status(&t))
                .sorted()
                .collect()
        }
    }

    impl<E: AsStatus> AsStatus for RequestError<E> {
        fn as_status(&self) -> Option<u16> {
            match self {
                RequestError::Timeout => None,
                RequestError::RequestWasNotValid => Some(422),
                RequestError::Unknown(_) => None,
                RequestError::Other(inner) => inner.as_status(),
            }
        }
    }

    impl AsStatus for CreateSessionErrorDiscriminants {
        fn as_status(&self) -> Option<u16> {
            Some(match self {
                Self::InvalidSessionId => {
                    // Arises from parsing the returned data, not an HTTP status code.
                    return None;
                }
                Self::RetryLater => 429,
            })
        }
    }

    impl AsStatus for ResumeSessionErrorDiscriminants {
        fn as_status(&self) -> Option<u16> {
            Some(match self {
                Self::InvalidSessionId => 400,
                Self::SessionNotFound => 404,
            })
        }
    }

    impl AsStatus for UpdateSessionErrorDiscriminants {
        fn as_status(&self) -> Option<u16> {
            Some(match self {
                Self::Rejected => 403,
                Self::RetryLater => 429,
            })
        }
    }

    impl AsStatus for RequestVerificationCodeErrorDiscriminants {
        fn as_status(&self) -> Option<u16> {
            Some(match self {
                Self::InvalidSessionId => 400,
                Self::SessionNotFound => 404,
                Self::NotReadyForVerification => 409,
                Self::SendFailed => 418, // 🫖
                Self::CodeNotDeliverable => 440,
                Self::RetryLater => 429,
            })
        }
    }

    impl AsStatus for SubmitVerificationErrorDiscriminants {
        fn as_status(&self) -> Option<u16> {
            Some(match self {
                Self::InvalidSessionId => 400,
                Self::SessionNotFound => 404,
                Self::NotReadyForVerification => 409,
                Self::RetryLater => 429,
            })
        }
    }

    impl AsStatus for CheckSvr2CredentialsErrorDiscriminants {
        fn as_status(&self) -> Option<u16> {
            Some(match self {
                Self::CredentialsCouldNotBeParsed => 422,
            })
        }
    }

    impl AsStatus for RegisterAccountErrorDiscriminants {
        fn as_status(&self) -> Option<u16> {
            Some(match self {
                Self::DeviceTransferIsPossibleButNotSkipped => 409,
                Self::RegistrationRecoveryVerificationFailed => 403,
                Self::RegistrationLock => 423,
                Self::RetryLater => 429,
            })
        }
    }

    #[test]
    fn error_type_status_mapping() {
        // This is just a re-hashing of the non-test logic but in a more easily
        // analyzable and auditable form.

        assert_eq!(CreateSessionError::sorted_statuses(), vec![422, 429]);
        assert_eq!(ResumeSessionError::sorted_statuses(), vec![400, 404, 422,]);
        assert_eq!(UpdateSessionError::sorted_statuses(), vec![403, 422, 429]);
        assert_eq!(
            RequestVerificationCodeError::sorted_statuses(),
            vec![400, 404, 409, 418, 422, 429, 440]
        );
        assert_eq!(
            SubmitVerificationError::sorted_statuses(),
            vec![400, 404, 409, 422, 429]
        );
        assert_eq!(
            RegisterAccountError::sorted_statuses(),
            vec![403, 409, 422, 423, 429]
        );
    }

    fn error_for_status(status: u16) -> ResponseError {
        let mut response_headers = HeaderMap::new();
        let mut response_body = None;
        match status {
            422 => return ResponseError::InvalidRequest,
            423 => {
                response_headers.append(CONTENT_TYPE_JSON.0, CONTENT_TYPE_JSON.1);
                response_body = Some(
                    serde_json::to_vec(&serde_json::json!({
                        "timeRemaining": 1234,
                        "svr2Credentials": {
                            "username": "username",
                            "password": "password",
                        }
                    }))
                    .unwrap()
                    .into(),
                )
            }
            429 => {
                return ResponseError::RetryLater(RetryLater {
                    retry_after_seconds: 30,
                })
            }
            440 => {
                response_headers.append(CONTENT_TYPE_JSON.0, CONTENT_TYPE_JSON.1);
                response_body = Some(
                    serde_json::to_vec(&serde_json::json!({
                        "reason": "providerRejected",
                        "permanentFailure": true
                    }))
                    .unwrap()
                    .into(),
                )
            }
            _ => {}
        }
        ResponseError::UnrecognizedStatus {
            status: StatusCode::from_u16(status).unwrap(),
            response_headers,
            response_body,
        }
    }

    fn round_trip_all_variants<T>()
    where
        T: CollectSortedStatuses + IntoDiscriminant<Discriminant: AsStatus> + Debug,
        RequestError<SessionRequestError>: Into<RequestError<T>>,
    {
        for status in T::sorted_statuses() {
            let error = error_for_status(status);
            println!("status = {status}, error = {error:?}");
            let request_error = RequestError::<SessionRequestError>::from(error);
            let inner = match request_error.into() {
                RequestError::RequestWasNotValid => continue,
                RequestError::Other(inner) => inner,
                e @ (RequestError::Timeout | RequestError::Unknown(_)) => {
                    unreachable!("unexpected {e:?}")
                }
            };
            assert_eq!(inner.discriminant().as_status(), Some(status));
        }
    }

    /// No-op, used to communicate the type `T` via type inference.
    fn e<T>(_: T) {}

    #[test_case(e::<CreateSessionError>)]
    #[test_case(e::<ResumeSessionError>)]
    #[test_case(e::<UpdateSessionError>)]
    #[test_case(e::<RequestVerificationCodeError>)]
    #[test_case(e::<SubmitVerificationError>)]
    #[test_case(e::<CheckSvr2CredentialsError>)]
    #[test_case(e::<RegisterAccountError>)]
    fn error_type_from_status<T>(_type_hint: fn(T))
    where
        RequestError<SessionRequestError>: Into<RequestError<T>>,
        T: CollectSortedStatuses + IntoDiscriminant<Discriminant: AsStatus> + Debug,
    {
        round_trip_all_variants::<T>();
    }
}
