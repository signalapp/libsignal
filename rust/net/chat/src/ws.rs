//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! The `ws` module and its submodules implement a chat server based on REST-like requests over a
//! websocket, as implemented in [`libsignal_net::chat`].

mod profiles;
mod usernames;

use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use libsignal_net::chat;
use libsignal_net::infra::errors::LogSafeDisplay;
use libsignal_net::infra::{extract_retry_later, AsHttpHeader};

use crate::api::{RequestError, UserBasedAuthorization};

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

impl<E> From<chat::SendError> for RequestError<E> {
    fn from(value: chat::SendError) -> Self {
        match value {
            chat::SendError::RequestTimedOut | chat::SendError::Disconnected => {
                RequestError::Timeout
            }
            chat::SendError::ConnectedElsewhere => RequestError::ConnectedElsewhere,
            chat::SendError::ConnectionInvalidated => RequestError::ConnectionInvalidated,
            e @ (chat::SendError::WebSocket(_)
            | chat::SendError::IncomingDataInvalid
            | chat::SendError::RequestHasInvalidHeader) => RequestError::Transport {
                log_safe: (&e as &dyn LogSafeDisplay).to_string(),
            },
        }
    }
}

/// Errors that arise from processing a response to a received request.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub(super) enum ResponseError {
    /// unexpected response status {status}
    UnrecognizedStatus {
        /// Pulled out for easier matching and displaying.
        status: http::StatusCode,
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

impl ResponseError {
    /// Converts a `ResponseError` into a [`RequestError`] by calling `map_unrecognized` for any
    /// non-success status codes.
    ///
    /// If `map_unrecognized` returns `None`, some basic checks will be done for request-independent
    /// response codes (like 429 Too Many Requests).
    fn into_request_error<E>(
        self,
        operation: &'static str,
        map_unrecognized: impl FnOnce(&chat::Response) -> Option<E>,
    ) -> RequestError<E> {
        match self {
            e @ (ResponseError::UnexpectedContentType(_)
            | ResponseError::MissingBody
            | ResponseError::InvalidJson
            | ResponseError::UnexpectedData) => RequestError::Unexpected {
                log_safe: e.to_string(),
            },
            ResponseError::UnrecognizedStatus { status, response } => {
                log::warn!("{operation}: {status} response");
                match map_unrecognized(&response) {
                    Some(specific_error) => RequestError::Other(specific_error),
                    None => {
                        let chat::Response {
                            status,
                            message,
                            body,
                            headers,
                        } = &response;

                        log::debug!(
                            "{operation}: got unsuccessful response with {status} {}: {:?}",
                            message.as_deref().unwrap_or_default(),
                            DebugAsStrOrBytes(body.as_deref().unwrap_or_default())
                        );

                        if status.is_server_error() {
                            return RequestError::ServerSideError;
                        }
                        if status.as_u16() == 429 {
                            if let Some(retry_later) = extract_retry_later(headers) {
                                return RequestError::RetryLater(retry_later);
                            }
                        }
                        if status.as_u16() == 428 {
                            #[derive(serde::Deserialize)]
                            struct ChallengeBody {
                                token: String,
                                // TODO: Move this type into libsignal-net-chat.
                                options: Vec<libsignal_net::registration::RequestedInformation>,
                            }

                            if let Ok(ChallengeBody { token, options }) =
                                parse_json_from_body(&response)
                            {
                                return RequestError::Challenge { token, options };
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
                }
            }
        }
    }
}

/// A trait for decoding typed responses from [`chat::Response`].
///
/// Defined this way (instead of with `Self` as the typed response) so that `try_into_response`
/// becomes available on `chat::Response` with a useful Jump to Definition (as opposed to the usual
/// From/Into idiom).
trait TryIntoResponse<R>: Sized {
    #[allow(clippy::result_large_err)] // ResponseError itself contains a chat::Response.
    fn try_into_response(self) -> Result<R, ResponseError>;
}

/// Marker type for a response with no expected body.
///
/// Necessary because `()` implements `serde::Deserialize`, so it looks like a valid JSON body to
/// the type system.
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

const JSON_CONTENT_TYPE: http::HeaderValue = http::HeaderValue::from_static("application/json");

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
    if content_type != Some(&JSON_CONTENT_TYPE) {
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

struct DebugAsStrOrBytes<'b>(&'b [u8]);
impl std::fmt::Debug for DebugAsStrOrBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match std::str::from_utf8(self.0) {
            Ok(s) => s.fmt(f),
            Err(_) => hex::encode(self.0).fmt(f),
        }
    }
}
