//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! The `ws` module and its submodules implement a chat server based on REST-like requests over a
//! websocket, as implemented in [`libsignal_net::chat`].

mod keytrans;
mod messages;
mod profiles;
// TODO make this not pub(crate)
pub(crate) mod registration;
mod usernames;

use std::future::Future;
use std::time::Duration;

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use http::StatusCode;
use libsignal_net::chat;
use libsignal_net::infra::errors::LogSafeDisplay;
use libsignal_net::infra::{AsHttpHeader, extract_retry_later};
use serde_with::serde_as;

use crate::api::{
    ChallengeOption, DisconnectedError, RateLimitChallenge, RequestError, UserBasedAuthorization,
};
use crate::logging::DebugAsStrOrBytes;

const ACCESS_KEY_HEADER_NAME: http::HeaderName =
    http::HeaderName::from_static("unidentified-access-key");
const GROUP_SEND_TOKEN_HEADER_NAME: http::HeaderName =
    http::HeaderName::from_static("group-send-token");

impl AsHttpHeader for UserBasedAuthorization {
    fn as_header(&self) -> (http::HeaderName, http::HeaderValue) {
        match self {
            UserBasedAuthorization::AccessKey(key) => (
                ACCESS_KEY_HEADER_NAME,
                BASE64_STANDARD.encode(key).parse().expect("valid"),
            ),
            UserBasedAuthorization::Group(token) => (
                GROUP_SEND_TOKEN_HEADER_NAME,
                BASE64_STANDARD
                    .encode(zkgroup::serialize(&token))
                    .parse()
                    .expect("valid"),
            ),
        }
    }
}

/// Marker type for use in [`crate::api`] traits.
pub enum OverWs {}

/// An abstraction over [`chat::ChatConnection`].
pub trait WsConnection: Sync {
    fn send(
        &self,
        log_tag: &'static str,
        log_safe_path: &str,
        request: chat::Request,
    ) -> impl Future<Output = Result<chat::Response, chat::SendError>> + Send;
}

impl WsConnection for chat::ChatConnection {
    async fn send(
        &self,
        log_tag: &'static str,
        log_safe_path: &str,
        request: chat::Request,
    ) -> Result<chat::Response, chat::SendError> {
        let request_id = rand::random::<u16>();
        let method = request.method.clone();
        log::info!("[{log_tag} {request_id:04x}] {method} {log_safe_path}");

        // TODO: Figure out timeouts for libsignal-net-chat APIs.
        let result = self.send(request, Duration::MAX).await;

        match &result {
            Ok(response) => {
                if response.status.is_success() {
                    log::info!(
                        "[{log_tag} {request_id:04x}] {method} {log_safe_path} {}",
                        response.status
                    )
                } else {
                    log::warn!(
                        "[{log_tag} {request_id:04x}] {method} {log_safe_path} {}",
                        response.status
                    );
                    log::debug!(
                        "[{log_tag} {request_id:04x}] {} {}: {:?}",
                        response.status,
                        response.message.as_deref().unwrap_or_default(),
                        DebugAsStrOrBytes(response.body.as_deref().unwrap_or_default())
                    );
                }
            }
            Err(e) => log::warn!(
                "[{log_tag} {request_id:04x}] {method} {log_safe_path} - {}",
                e as &dyn LogSafeDisplay
            ),
        }

        result
    }
}

impl<E> From<chat::SendError> for RequestError<E> {
    fn from(value: chat::SendError) -> Self {
        match value {
            chat::SendError::RequestTimedOut => return RequestError::Timeout,
            chat::SendError::Disconnected => DisconnectedError::Closed,
            chat::SendError::ConnectedElsewhere => DisconnectedError::ConnectedElsewhere,
            chat::SendError::ConnectionInvalidated => DisconnectedError::ConnectionInvalidated,
            e @ (chat::SendError::WebSocket(_)
            | chat::SendError::IncomingDataInvalid
            | chat::SendError::RequestHasInvalidHeader) => DisconnectedError::Transport {
                log_safe: (&e as &dyn LogSafeDisplay).to_string(),
            },
        }
        .into()
    }
}

/// Errors that arise from processing a response to a received request.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub(super) enum ResponseError {
    /// unexpected response status {status}
    UnrecognizedStatus {
        /// Pulled out for easier matching and displaying.
        status: StatusCode,
        response: chat::Response,
    },
    /// unexpected content-type {0:?}
    UnexpectedContentType(Option<http::HeaderValue>),
    /// response had no body
    MissingBody,
    /// response body was not valid JSON
    InvalidJson,
    /// response body didn't match the schema
    UnexpectedData,
}
impl LogSafeDisplay for ResponseError {}

pub(crate) enum CustomError<E> {
    NoCustomHandling,
    Err(E),
    Unexpected { log_safe: String },
}

impl<E> CustomError<E> {
    /// A convenience method to be used with [`ResponseError::into_request_error`] that always
    /// produces `NoCustomHandling`.
    fn no_custom_handling(_: &chat::Response) -> Self {
        Self::NoCustomHandling
    }
}

impl<E> From<E> for CustomError<E> {
    fn from(value: E) -> Self {
        Self::Err(value)
    }
}

impl ResponseError {
    /// Converts a `ResponseError` into a [`RequestError`] by calling `map_unrecognized` for any
    /// non-success status codes.
    ///
    /// If `map_unrecognized` returns `None`, some basic checks will be done for request-independent
    /// response codes (like 429 Too Many Requests).
    pub(crate) fn into_request_error<E, D>(
        self,
        map_unrecognized: impl FnOnce(&chat::Response) -> CustomError<E>,
    ) -> RequestError<E, D> {
        match self {
            e @ (ResponseError::UnexpectedContentType(_)
            | ResponseError::MissingBody
            | ResponseError::InvalidJson
            | ResponseError::UnexpectedData) => RequestError::Unexpected {
                log_safe: e.to_string(),
            },
            ResponseError::UnrecognizedStatus {
                status: _,
                response,
            } => match map_unrecognized(&response) {
                CustomError::Err(specific_error) => RequestError::Other(specific_error),
                CustomError::Unexpected { log_safe } => RequestError::Unexpected { log_safe },
                CustomError::NoCustomHandling => {
                    let chat::Response {
                        status,
                        message: _,
                        headers,
                        body: _,
                    } = &response;

                    if status.is_server_error() {
                        return RequestError::ServerSideError;
                    }
                    if status.as_u16() == 429 {
                        if let Some(retry_later) = extract_retry_later(headers) {
                            return RequestError::RetryLater(retry_later);
                        }
                    }
                    if status.as_u16() == 428 {
                        #[serde_as]
                        #[derive(serde::Deserialize)]
                        struct ChallengeBody {
                            token: String,
                            #[serde_as(as = "Vec<serde_with::DisplayFromStr>")]
                            options: Vec<ChallengeOption>,
                        }

                        if let Ok(ChallengeBody { token, options }) =
                            parse_json_from_body(&response)
                        {
                            return RequestError::Challenge(RateLimitChallenge { token, options });
                        }
                    }
                    if status.as_u16() == 422 {
                        return RequestError::Unexpected {
                            log_safe: "the request did not pass server validation".into(),
                        };
                    }

                    RequestError::Unexpected {
                        log_safe: format!("unexpected response status {status}"),
                    }
                }
            },
        }
    }
}

/// A trait for decoding typed responses from [`chat::Response`].
///
/// Defined this way (instead of with `Self` as the typed response) so that `try_into_response`
/// becomes available on `chat::Response` with a useful Jump to Definition (as opposed to the usual
/// From/Into idiom).
pub(super) trait TryIntoResponse<R>: Sized {
    #[allow(clippy::result_large_err)] // ResponseError itself contains a chat::Response.
    fn try_into_response(self) -> Result<R, ResponseError>;
}

/// Marker type for a response with no expected body.
///
/// Necessary because `()` implements `serde::Deserialize`, so it looks like a valid JSON body to
/// the type system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Empty;

impl TryIntoResponse<Empty> for chat::Response {
    fn try_into_response(self) -> Result<Empty, ResponseError> {
        let chat::Response {
            status: _,
            message: _,
            body,
            headers,
        } = &check_response_status(self)?;

        let content_type = headers.get(http::header::CONTENT_TYPE);
        if content_type.is_some() {
            return Err(ResponseError::UnexpectedContentType(content_type.cloned()));
        }
        if body.is_some() {
            return Err(ResponseError::UnexpectedData);
        }

        Ok(Empty)
    }
}

const CONTENT_TYPE_JSON: (http::HeaderName, http::HeaderValue) = (
    http::header::CONTENT_TYPE,
    http::HeaderValue::from_static("application/json"),
);

impl<R> TryIntoResponse<R> for chat::Response
where
    R: for<'a> serde::Deserialize<'a>,
{
    fn try_into_response(self) -> Result<R, ResponseError> {
        let response = check_response_status(self)?;
        parse_json_from_body(&response)
    }
}

#[allow(clippy::result_large_err)]
fn check_response_status(response: chat::Response) -> Result<chat::Response, ResponseError> {
    if response.status.is_success() {
        // TODO: warn on unusual success codes?
        Ok(response)
    } else {
        Err(ResponseError::UnrecognizedStatus {
            status: response.status,
            response,
        })
    }
}

/// Like [`TryIntoResponse`], but without checking the status code first.
#[expect(clippy::result_large_err)]
fn parse_json_from_body<R>(response: &chat::Response) -> Result<R, ResponseError>
where
    R: for<'a> serde::Deserialize<'a>,
{
    let chat::Response {
        status: _,
        message: _,
        body,
        headers,
    } = response;

    let content_type = headers.get(http::header::CONTENT_TYPE);
    if content_type != Some(&CONTENT_TYPE_JSON.1) {
        return Err(ResponseError::UnexpectedContentType(content_type.cloned()));
    }

    let body = body.as_ref().ok_or(ResponseError::MissingBody)?;
    serde_json::from_slice(body).map_err(|e| match e.classify() {
        serde_json::error::Category::Data => ResponseError::UnexpectedData,
        serde_json::error::Category::Syntax
        | serde_json::error::Category::Io
        | serde_json::error::Category::Eof => ResponseError::InvalidJson,
    })
}

#[cfg(test)]
mod testutil {
    use super::*;

    pub(crate) fn json(status: u16, body: impl AsRef<[u8]>) -> chat::Response {
        chat::Response {
            status: http::StatusCode::from_u16(status).expect("valid"),
            message: None,
            headers: http::HeaderMap::from_iter([CONTENT_TYPE_JSON]),
            body: Some(bytes::Bytes::copy_from_slice(body.as_ref())),
        }
    }

    pub(crate) fn empty(status: u16) -> chat::Response {
        chat::Response {
            status: http::StatusCode::from_u16(status).expect("valid"),
            message: None,
            headers: http::HeaderMap::new(),
            body: None,
        }
    }

    pub(crate) fn headers(
        status: u16,
        headers: &[(http::HeaderName, &'static str)],
    ) -> chat::Response {
        chat::Response {
            status: http::StatusCode::from_u16(status).expect("valid"),
            message: None,
            headers: headers
                .iter()
                .map(|(name, value)| (name.clone(), http::HeaderValue::from_static(value)))
                .collect(),
            body: None,
        }
    }

    pub(crate) struct RequestValidator {
        pub expected: chat::Request,
        pub response: chat::Response,
    }

    impl WsConnection for RequestValidator {
        fn send(
            &self,
            _log_tag: &'static str,
            _log_safe_path: &str,
            request: chat::Request,
        ) -> impl Future<Output = Result<chat::Response, chat::SendError>> + Send {
            pretty_assertions::assert_eq!(self.expected, request);
            std::future::ready(Ok(self.response.clone()))
        }
    }

    pub(crate) struct ProduceResponse(pub chat::Response);

    impl WsConnection for ProduceResponse {
        fn send(
            &self,
            _log_tag: &'static str,
            _log_safe_path: &str,
            _request: chat::Request,
        ) -> impl Future<Output = Result<chat::Response, chat::SendError>> + Send {
            std::future::ready(Ok(self.0.clone()))
        }
    }
}

#[cfg(test)]
mod test {
    use libsignal_net::infra::AsStaticHttpHeader as _;
    use libsignal_net::infra::errors::RetryLater;
    use test_case::test_case;

    use super::testutil::*;
    use super::*;
    use crate::api::ChallengeOption;

    #[test_case(empty(200) => matches Ok(Empty))]
    #[test_case(empty(204) => matches Ok(Empty))]
    #[test_case(json(200, "{}") => matches Err(RequestError::Unexpected { log_safe: m }) if m.contains("content-type"))]
    #[test_case(empty(500) => matches Err(RequestError::ServerSideError))]
    #[test_case(json(503, "{}") => matches Err(RequestError::ServerSideError))]
    #[test_case(empty(429) => matches Err(RequestError::Unexpected { log_safe: m }) if m.contains("429"))]
    #[test_case(headers(
        429, &[(RetryLater::HEADER_NAME, "5")]
    ) => matches Err(RequestError::RetryLater(RetryLater { retry_after_seconds: 5 })))]
    #[test_case(empty(428) => matches Err(RequestError::Unexpected { log_safe: m }) if m.contains("428"))]
    #[test_case(json(428, "{}") => matches Err(RequestError::Unexpected { log_safe: m }) if m.contains("428"))]
    #[test_case(json(
        428, r#"{"token": "zzz", "options": ["captcha"]}"#
    ) => matches Err(RequestError::Challenge(RateLimitChallenge { token, options })) if token == "zzz" && options == vec![ChallengeOption::Captcha])]
    #[test_case(empty(422) => matches Err(RequestError::Unexpected { log_safe: m }) if m.contains("server validation"))]
    #[test_case(empty(419) => matches Err(RequestError::Unexpected { log_safe: m }) if m.contains("419"))]
    fn try_parse_empty(
        input: chat::Response,
    ) -> Result<Empty, RequestError<std::convert::Infallible>> {
        input
            .try_into_response()
            .map_err(|e| e.into_request_error(CustomError::no_custom_handling))
    }

    #[derive(Debug, serde::Deserialize)]
    struct Example {
        foo: u8,
    }

    #[test_case(empty(200) => matches Err(RequestError::Unexpected { log_safe: m }) if m.contains("content-type"))]
    #[test_case(headers(
        200, &[(http::header::CONTENT_TYPE, "application/json")]
    ) => matches Err(RequestError::Unexpected { log_safe: m }) if m.contains("body"))]
    #[test_case(json(200, "{}") => matches Err(RequestError::Unexpected { log_safe: m }) if m.contains("body"))]
    #[test_case(json(200, r#"{"foo": 12}"#) => matches Ok(Example { foo: 12 }))]
    #[test_case(json(200, r#"{"foo": 12, "bar": 15}"#) => matches Ok(Example { foo: 12 }))]
    #[test_case(json(200, r#"{"foo": 300}"#) => matches Err(RequestError::Unexpected { log_safe: m }) if m.contains("body"))]
    #[test_case(
        chat::Response { headers: http::HeaderMap::new(), ..json(200, r#"{"foo": 12}"#) }
    => matches Err(RequestError::Unexpected { log_safe: m }) if m.contains("content-type"))]
    #[test_case(empty(500) => matches Err(RequestError::ServerSideError))]
    fn try_parse_json(
        input: chat::Response,
    ) -> Result<Example, RequestError<std::convert::Infallible>> {
        input
            .try_into_response()
            .map_err(|e| e.into_request_error(CustomError::no_custom_handling))
    }
}
