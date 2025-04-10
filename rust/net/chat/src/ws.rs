//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! The `ws` module and its submodules implement a chat server based on REST-like requests over a
//! websocket, as implemented in [`libsignal_net::chat`].

mod profiles;

use base64::prelude::BASE64_STANDARD;
use base64::Engine as _;
use libsignal_net::chat;
use libsignal_net::infra::errors::{LogSafeDisplay, RetryLater};
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

/// Errors that arise from a response to a received request.
///
/// This doesn't include timeouts, since the request was known to be received
/// and the server sent a response.
#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub(super) enum ResponseError {
    /// {0}
    RetryLater(RetryLater),
    /// the request did not pass server validation
    InvalidRequest,
    /// unexpected content-type {0:?}
    UnexpectedContentType(Option<http::HeaderValue>),
    /// unexpected response status {status}
    UnrecognizedStatus {
        status: http::StatusCode,
        response: chat::Response,
    },
    /// response had no body
    MissingBody,
    /// response body was not valid JSON
    InvalidJson,
    /// response body didn't match the schema
    UnexpectedData,
}
impl LogSafeDisplay for ResponseError {}

impl ResponseError {
    fn into_request_error<E>(
        self,
        map_unrecognized: impl FnOnce(chat::Response) -> Option<RequestError<E>>,
    ) -> RequestError<E> {
        match self {
            ResponseError::RetryLater(retry_later) => RequestError::RetryLater(retry_later),
            e @ (ResponseError::InvalidRequest
            | ResponseError::UnexpectedContentType(_)
            | ResponseError::MissingBody
            | ResponseError::InvalidJson
            | ResponseError::UnexpectedData) => RequestError::Unexpected {
                log_safe: e.to_string(),
            },
            ResponseError::UnrecognizedStatus { status, response } => map_unrecognized(response)
                .unwrap_or_else(|| RequestError::Unexpected {
                    log_safe: format!("unexpected response status {status}"),
                }),
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
#[allow(dead_code)]
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

impl<R> TryIntoResponse<R> for chat::Response
where
    R: for<'a> serde::Deserialize<'a>,
{
    fn try_into_response(self) -> Result<R, ResponseError> {
        let chat::Response {
            status: _,
            message: _,
            body,
            headers,
        } = &check_response_status(self)?;

        let content_type = headers.get(http::header::CONTENT_TYPE);
        if content_type != Some(&http::HeaderValue::from_static("application/json")) {
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
}

#[allow(clippy::result_large_err)]
fn check_response_status(response: chat::Response) -> Result<chat::Response, ResponseError> {
    let chat::Response {
        status,
        message: _,
        body,
        headers,
    } = &response;
    if !status.is_success() {
        if status.as_u16() == 429 {
            if let Some(retry_later) = extract_retry_later(headers) {
                return Err(ResponseError::RetryLater(retry_later));
            }
        }
        if status.as_u16() == 422 {
            return Err(ResponseError::InvalidRequest);
        }
        // TODO: Treat 5xx more like RetryLater than like a 4xx.
        log::debug!(
            "got unsuccessful response with {status}: {:?}",
            DebugAsStrOrBytes(body.as_deref().unwrap_or_default())
        );
        return Err(ResponseError::UnrecognizedStatus {
            status: *status,
            response,
        });
    }
    // TODO: warn on unusual success codes?
    Ok(response)
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
