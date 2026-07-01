//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use http::HeaderMap;
use libsignal_net::chat::Response as ChatResponse;

use crate::api::registration::{
    CheckSvr2CredentialsError, CreateSessionError, RegisterAccountError, RegistrationSession,
    RequestVerificationCodeError, ResumeSessionError, SubmitVerificationError, UpdateSessionError,
    WithRecoveredSession,
};
use crate::api::{AllowRateLimitChallenges, RequestError};
use crate::ws::{CustomError, ResponseError, parse_json_from_body};

// Rate limit challenges are allowed for all registration requests.
const ALLOW_RATE_LIMIT_CHALLENGES: AllowRateLimitChallenges = AllowRateLimitChallenges::Yes;

impl<D> From<ResponseError> for RequestError<UpdateSessionError, D> {
    fn from(value: ResponseError) -> Self {
        value.into_request_error(ALLOW_RATE_LIMIT_CHALLENGES, |value| {
            let ChatResponse { status, .. } = value;
            match status.as_u16() {
                403 => CustomError::Err(UpdateSessionError::Rejected),
                _ => CustomError::NoCustomHandling,
            }
        })
    }
}

impl<D> From<ResponseError> for RequestError<CreateSessionError, D> {
    fn from(value: ResponseError) -> Self {
        value.into_request_error(ALLOW_RATE_LIMIT_CHALLENGES, CustomError::no_custom_handling)
    }
}

impl<D> From<ResponseError> for RequestError<ResumeSessionError, D> {
    fn from(value: ResponseError) -> Self {
        value.into_request_error(ALLOW_RATE_LIMIT_CHALLENGES, |value| {
            let ChatResponse { status, .. } = value;
            CustomError::Err(match status.as_u16() {
                404 => ResumeSessionError::SessionNotFound,
                400 => ResumeSessionError::InvalidSessionId,
                _ => {
                    return CustomError::NoCustomHandling;
                }
            })
        })
    }
}

fn session_state_from_json_body(
    headers: &HeaderMap,
    body: Option<&[u8]>,
) -> Option<RegistrationSession> {
    parse_json_from_body(headers, Some(body?)).ok()
}

impl<D> From<ResponseError> for RequestError<RequestVerificationCodeError, D> {
    fn from(value: ResponseError) -> Self {
        value.into_request_error(ALLOW_RATE_LIMIT_CHALLENGES, |value| {
            let ChatResponse {
                status,
                body,
                headers,
                ..
            } = value;
            CustomError::Err(match status.as_u16() {
                400 => RequestVerificationCodeError::InvalidSessionId,
                404 => RequestVerificationCodeError::SessionNotFound,
                409 => RequestVerificationCodeError::NotReadyForVerification(
                    session_state_from_json_body(headers, body.as_deref()),
                ),
                418 => RequestVerificationCodeError::SendFailed(session_state_from_json_body(
                    headers,
                    body.as_deref(),
                )),
                440 => {
                    let Some(not_deliverable) = body
                        .as_deref()
                        .and_then(|body| parse_json_from_body(headers, Some(body)).ok())
                    else {
                        return CustomError::NoCustomHandling;
                    };
                    RequestVerificationCodeError::CodeNotDeliverable(not_deliverable)
                }
                _ => {
                    return CustomError::NoCustomHandling;
                }
            })
        })
    }
}

impl<D> From<ResponseError> for RequestError<SubmitVerificationError, D> {
    fn from(value: ResponseError) -> Self {
        value.into_request_error(ALLOW_RATE_LIMIT_CHALLENGES, |value| {
            let ChatResponse {
                status,
                message: _,
                headers,
                body,
            } = value;
            CustomError::Err(match status.as_u16() {
                400 => SubmitVerificationError::InvalidSessionId,
                404 => SubmitVerificationError::SessionNotFound,
                409 => SubmitVerificationError::NotReadyForVerification(
                    session_state_from_json_body(headers, body.as_deref()),
                ),
                _ => return CustomError::NoCustomHandling,
            })
        })
    }
}

/// Recovers session state carried in the body of a failure response whose status
/// is one of `statuses`.
///
/// The status list is explicit rather than "any body that parses" because some
/// failure bodies (e.g. a 440's [`VerificationCodeNotDeliverable`]) would parse
/// into an all-default [`RegistrationSession`] and wrongly update the cache.
///
/// [`VerificationCodeNotDeliverable`]: crate::api::registration::VerificationCodeNotDeliverable
fn recover_session_for_statuses(
    response: &ChatResponse,
    statuses: &[u16],
) -> Option<RegistrationSession> {
    let ChatResponse {
        status,
        message: _,
        headers,
        body,
    } = response;
    statuses
        .contains(&status.as_u16())
        .then(|| session_state_from_json_body(headers, body.as_deref()))
        .flatten()
}

/// Session state an endpoint may carry in a failure response body.
///
/// This covers every status whose body carries session state, both the ones
/// that turn into a typed error (409, 418) and the ones that come back as a
/// generic error (429), so the caller can refresh its cache uniformly.
///
/// Defaults to none; endpoints whose responses carry it override.
trait RecoverSession {
    fn recover_session(_response: &ChatResponse) -> Option<RegistrationSession> {
        None
    }
}

impl RecoverSession for ResumeSessionError {}
impl RecoverSession for UpdateSessionError {}
impl RecoverSession for RequestVerificationCodeError {
    fn recover_session(response: &ChatResponse) -> Option<RegistrationSession> {
        recover_session_for_statuses(response, &[409, 418, 429])
    }
}
impl RecoverSession for SubmitVerificationError {
    fn recover_session(response: &ChatResponse) -> Option<RegistrationSession> {
        recover_session_for_statuses(response, &[409, 429])
    }
}

/// Pairs the plain error conversion with any session recovered from the response.
impl<E: RecoverSession, D> From<ResponseError> for WithRecoveredSession<RequestError<E, D>>
where
    RequestError<E, D>: From<ResponseError>,
{
    fn from(value: ResponseError) -> Self {
        let session = match &value {
            ResponseError::UnrecognizedStatus { response, .. } => E::recover_session(response),
            _ => None,
        };
        WithRecoveredSession {
            result: value.into(),
            session,
        }
    }
}

impl<D> From<ResponseError> for RequestError<CheckSvr2CredentialsError, D> {
    fn from(value: ResponseError) -> Self {
        value.into_request_error(ALLOW_RATE_LIMIT_CHALLENGES, |value| {
            let ChatResponse { status, .. } = value;
            match status.as_u16() {
                422 => CustomError::Err(CheckSvr2CredentialsError::CredentialsCouldNotBeParsed),
                _ => CustomError::NoCustomHandling,
            }
        })
    }
}

impl<D> From<ResponseError> for RequestError<RegisterAccountError, D> {
    fn from(value: ResponseError) -> Self {
        value.into_request_error(ALLOW_RATE_LIMIT_CHALLENGES, |value| {
            let ChatResponse {
                headers,
                status,
                body,
                ..
            } = value;
            CustomError::Err(match status.as_u16() {
                403 => RegisterAccountError::RegistrationRecoveryVerificationFailed,
                409 => RegisterAccountError::DeviceTransferIsPossibleButNotSkipped,
                423 => {
                    let Some(registration_lock) = body
                        .as_deref()
                        .and_then(|body| parse_json_from_body(headers, Some(body)).ok())
                    else {
                        return CustomError::NoCustomHandling;
                    };
                    RegisterAccountError::RegistrationLock(registration_lock)
                }
                _ => return CustomError::NoCustomHandling,
            })
        })
    }
}

#[cfg(test)]
mod test {
    use std::convert::Infallible;
    use std::fmt::Debug;

    use http::{HeaderMap, StatusCode};
    use itertools::Itertools;
    use libsignal_net::infra::AsHttpHeader;
    use libsignal_net::infra::errors::RetryLater;
    use strum::{IntoDiscriminant, IntoEnumIterator};
    use test_case::test_case;

    use super::*;
    use crate::api::RateLimitChallenge;
    use crate::api::registration::{
        CheckSvr2CredentialsErrorDiscriminants, CreateSessionErrorDiscriminants,
        RegisterAccountErrorDiscriminants, RequestVerificationCodeErrorDiscriminants,
        ResumeSessionErrorDiscriminants, SubmitVerificationErrorDiscriminants,
        UpdateSessionErrorDiscriminants,
    };
    use crate::ws::CONTENT_TYPE_JSON;

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
                .chain([RequestError::RetryLater(RetryLater {
                    retry_after_seconds: 30,
                })])
                .filter_map(|t| RequestError::<T::Discriminant, Infallible>::as_status(&t))
                .sorted()
                .collect()
        }
    }

    impl<E: AsStatus> AsStatus for RequestError<E, Infallible> {
        fn as_status(&self) -> Option<u16> {
            match self {
                RequestError::Timeout => None,
                RequestError::Other(inner) => inner.as_status(),
                RequestError::RetryLater(retry_later) => retry_later.as_status(),
                RequestError::Challenge(challenge) => challenge.as_status(),
                RequestError::ServerSideError | RequestError::Unexpected { log_safe: _ } => None,
                RequestError::Disconnected(d) => match *d {},
            }
        }
    }

    impl AsStatus for RetryLater {
        fn as_status(&self) -> Option<u16> {
            Some(429)
        }
    }

    impl AsStatus for RateLimitChallenge {
        fn as_status(&self) -> Option<u16> {
            Some(428)
        }
    }

    impl AsStatus for CreateSessionErrorDiscriminants {
        fn as_status(&self) -> Option<u16> {
            match self {
                Self::InvalidSessionId => {
                    // Arises from parsing the returned data, not an HTTP status code.
                    None
                }
            }
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
            })
        }
    }

    impl AsStatus for SubmitVerificationErrorDiscriminants {
        fn as_status(&self) -> Option<u16> {
            Some(match self {
                Self::InvalidSessionId => 400,
                Self::SessionNotFound => 404,
                Self::NotReadyForVerification => 409,
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
            })
        }
    }

    #[test]
    fn error_type_status_mapping() {
        // This is just a re-hashing of the non-test logic but in a more easily
        // analyzable and auditable form.

        assert_eq!(CreateSessionError::sorted_statuses(), vec![429]);
        assert_eq!(ResumeSessionError::sorted_statuses(), vec![400, 404, 429]);
        assert_eq!(UpdateSessionError::sorted_statuses(), vec![403, 429]);
        assert_eq!(
            RequestVerificationCodeError::sorted_statuses(),
            vec![400, 404, 409, 418, 429, 440]
        );
        assert_eq!(
            SubmitVerificationError::sorted_statuses(),
            vec![400, 404, 409, 429]
        );
        assert_eq!(
            RegisterAccountError::sorted_statuses(),
            vec![403, 409, 423, 429]
        );
    }

    fn error_for_status(status: u16) -> ResponseError {
        let mut response_headers = HeaderMap::new();
        let mut response_body = None;
        match status {
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
            429 => response_headers.extend([RetryLater {
                retry_after_seconds: 30,
            }
            .as_header()]),
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
        let status = StatusCode::from_u16(status).unwrap();
        ResponseError::UnrecognizedStatus {
            status,
            response: ChatResponse {
                status,
                message: None,
                headers: response_headers,
                body: response_body,
            },
        }
    }

    fn round_trip_all_variants<T>()
    where
        T: CollectSortedStatuses + IntoDiscriminant<Discriminant: AsStatus> + Debug,
        RequestError<T, Infallible>: From<ResponseError>,
    {
        for status in T::sorted_statuses() {
            let error = error_for_status(status);
            println!("status = {status}, error = {error:?}");
            let request_error = RequestError::<T, Infallible>::from(error);
            println!("request error: {request_error:?}");
            let error_status = match request_error {
                RequestError::Other(inner) => inner.discriminant().as_status(),
                RequestError::RetryLater(retry) => retry.as_status(),
                e @ (RequestError::Timeout
                | RequestError::ServerSideError
                | RequestError::Challenge { .. }
                | RequestError::Unexpected { .. }) => {
                    unreachable!("unexpected {e:?}")
                }
                RequestError::Disconnected(d) => match d {},
            };
            assert_eq!(error_status, Some(status));
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
        RequestError<T, Infallible>: From<ResponseError>,
        T: CollectSortedStatuses + IntoDiscriminant<Discriminant: AsStatus> + Debug,
    {
        round_trip_all_variants::<T>();
    }
}
