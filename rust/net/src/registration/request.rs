use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

use http::uri::PathAndQuery;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use libsignal_net_infra::errors::{LogSafeDisplay, RetryLater};
use libsignal_net_infra::extract_retry_later;
use serde_with::{serde_as, skip_serializing_none, DurationSeconds};

use crate::registration::SessionId;

pub(super) const CONTENT_TYPE_JSON: (HeaderName, HeaderValue) = (
    http::header::CONTENT_TYPE,
    HeaderValue::from_static("application/json"),
);

#[derive(Clone, Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateSession {
    pub number: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_token_type: Option<PushTokenType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mnc: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GetSession {}

#[serde_as]
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(rename_all = "camelCase", default)]
pub struct RegistrationSession {
    pub allowed_to_request_code: bool,
    pub verified: bool,
    #[serde_as(as = "Option<DurationSeconds>")]
    pub next_sms: Option<Duration>,
    #[serde_as(as = "Option<DurationSeconds>")]
    pub next_call: Option<Duration>,
    #[serde_as(as = "Option<DurationSeconds>")]
    pub next_verification_attempt: Option<Duration>,
    pub requested_information: HashSet<RequestedInformation>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Deserialize, strum::AsRefStr)]
#[strum(serialize_all = "camelCase")]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(serde::Serialize))]
pub enum RequestedInformation {
    PushChallenge,
    Captcha,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize, strum::EnumString)]
#[strum(serialize_all = "camelCase")]
#[serde(rename_all = "camelCase")]
pub enum PushTokenType {
    Apn,
    Fcm,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize, strum::EnumString)]
#[strum(serialize_all = "camelCase")]
#[serde(rename_all = "camelCase")]
pub enum VerificationTransport {
    Sms,
    Voice,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VerificationCodeNotDeliverable {
    // This could be a stronger type but we don't need it to be in libsignal and
    // the additional flexibility could be useful if the server adds more
    // "reason" values.
    reason: String,
    permanent_failure: bool,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct UpdateRegistrationSession<'a> {
    pub(super) captcha: Option<&'a str>,
    pub(super) push_token: Option<&'a str>,
    pub(crate) push_token_type: Option<PushTokenType>,
    pub(crate) push_challenge: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RequestVerificationCode<'a> {
    pub(super) transport: VerificationTransport,
    pub(super) client: &'a str,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct SubmitVerificationCode<'a> {
    pub(super) code: &'a str,
}

pub(super) struct RegistrationRequest<'s, R> {
    pub(super) session_id: &'s SessionId,
    pub(super) request: R,
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
    UnexpectedContentType(Option<HeaderValue>),
    /// unexpected response status {status}
    UnrecognizedStatus {
        status: StatusCode,
        response_headers: HeaderMap,
        response_body: Option<Box<[u8]>>,
    },
    /// response had no body
    MissingBody,
    /// response body was not valid JSON
    InvalidJson,
    /// response body didn't match the schema
    UnexpectedData,
}
impl LogSafeDisplay for ResponseError {}

#[derive(Debug, Default, PartialEq, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(rename_all = "camelCase")]
pub(super) struct RegistrationResponse {
    #[serde(rename = "id")]
    pub(super) session_id: String,
    #[serde(flatten)]
    pub(super) session: RegistrationSession,
}

impl VerificationCodeNotDeliverable {
    pub(crate) fn from_response(
        response_headers: &HeaderMap,
        response_body: &[u8],
    ) -> Option<Self> {
        if response_headers.get(CONTENT_TYPE_JSON.0) != Some(&CONTENT_TYPE_JSON.1) {
            return None;
        }

        serde_json::from_slice(response_body).ok()
    }
}

/// A value that can be sent to the server as part of a REST request.
pub(super) trait Request {
    /// The HTTP [`Method`] to send the request with
    const METHOD: Method;

    /// The HTTP path to use when sending the request.
    fn request_path(session_id: &SessionId) -> PathAndQuery;

    /// The serialized JSON for the request body, if any.
    fn into_json_body(self) -> Option<Box<[u8]>>;
}

impl Request for GetSession {
    const METHOD: Method = Method::GET;
    fn request_path(session_id: &SessionId) -> PathAndQuery {
        format!(
            "{VERIFICATION_SESSION_PATH_PREFIX}/{}",
            session_id.as_url_path_segment()
        )
        .parse()
        .unwrap()
    }
    fn into_json_body(self) -> Option<Box<[u8]>> {
        None
    }
}

impl Request for UpdateRegistrationSession<'_> {
    const METHOD: Method = Method::PATCH;
    fn request_path(session_id: &SessionId) -> PathAndQuery {
        GetSession::request_path(session_id)
    }
    fn into_json_body(self) -> Option<Box<[u8]>> {
        Some(
            serde_json::to_vec(&self)
                .expect("no maps")
                .into_boxed_slice(),
        )
    }
}

impl Request for RequestVerificationCode<'_> {
    const METHOD: Method = Method::POST;
    fn request_path(session_id: &SessionId) -> PathAndQuery {
        format!(
            "{VERIFICATION_SESSION_PATH_PREFIX}/{}/code",
            session_id.as_url_path_segment()
        )
        .parse()
        .unwrap()
    }
    fn into_json_body(self) -> Option<Box<[u8]>> {
        Some(
            serde_json::to_vec(&self)
                .expect("no maps")
                .into_boxed_slice(),
        )
    }
}

impl Request for SubmitVerificationCode<'_> {
    const METHOD: Method = Method::PUT;
    fn request_path(session_id: &SessionId) -> PathAndQuery {
        RequestVerificationCode::request_path(session_id)
    }
    fn into_json_body(self) -> Option<Box<[u8]>> {
        Some(
            serde_json::to_vec(&self)
                .expect("no maps")
                .into_boxed_slice(),
        )
    }
}

impl TryFrom<crate::chat::Response> for RegistrationResponse {
    type Error = ResponseError;

    fn try_from(value: crate::chat::Response) -> Result<Self, Self::Error> {
        let crate::chat::Response {
            status,
            message: _,
            body,
            headers,
        } = value;
        if !status.is_success() {
            if status.as_u16() == 429 {
                if let Some(retry_later) = extract_retry_later(&headers) {
                    return Err(ResponseError::RetryLater(retry_later));
                }
            }
            if status.as_u16() == 422 {
                return Err(ResponseError::InvalidRequest);
            }
            log::debug!(
                "got unsuccessful response with {status}: {:?}",
                DebugAsStrOrBytes(body.as_deref().unwrap_or_default())
            );
            return Err(ResponseError::UnrecognizedStatus {
                status,
                response_headers: headers,
                response_body: body,
            });
        }
        let content_type = headers.get(http::header::CONTENT_TYPE);
        if content_type != Some(&HeaderValue::from_static("application/json")) {
            return Err(ResponseError::UnexpectedContentType(content_type.cloned()));
        }

        let body = body.ok_or(ResponseError::MissingBody)?;
        serde_json::from_slice(&body).map_err(|e| match e.classify() {
            serde_json::error::Category::Data => ResponseError::UnexpectedData,
            serde_json::error::Category::Syntax
            | serde_json::error::Category::Io
            | serde_json::error::Category::Eof => ResponseError::InvalidJson,
        })
    }
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

const VERIFICATION_SESSION_PATH_PREFIX: &str = "/v1/verification/session";

impl From<CreateSession> for crate::chat::Request {
    fn from(value: CreateSession) -> Self {
        let body = serde_json::to_vec(&value)
            .expect("no maps")
            .into_boxed_slice();
        Self {
            method: Method::POST,
            headers: HeaderMap::from_iter([CONTENT_TYPE_JSON]),
            path: PathAndQuery::from_static(VERIFICATION_SESSION_PATH_PREFIX),
            body: Some(body),
        }
    }
}

impl<'s, R: Request> From<RegistrationRequest<'s, R>> for crate::chat::Request {
    fn from(value: RegistrationRequest<'s, R>) -> Self {
        let RegistrationRequest {
            session_id,
            request,
        } = value;

        let path = R::request_path(session_id);
        let body = request.into_json_body();
        let headers = HeaderMap::from_iter(body.is_some().then_some(CONTENT_TYPE_JSON));

        Self {
            method: R::METHOD,
            headers,
            path,
            body,
        }
    }
}

impl TryFrom<String> for VerificationTransport {
    type Error = <Self as FromStr>::Err;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        FromStr::from_str(&value)
    }
}

#[cfg(test)]
impl RegistrationResponse {
    pub(super) fn into_websocket_response(
        self,
        ws_request_id: u64,
    ) -> crate::proto::chat_websocket::WebSocketResponseMessage {
        crate::proto::chat_websocket::WebSocketResponseMessage {
            id: Some(ws_request_id),
            status: Some(http::StatusCode::OK.as_u16().into()),
            message: Some("OK".to_string()),
            headers: vec!["content-type: application/json".to_owned()],
            body: Some(serde_json::to_vec(&self).unwrap()),
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr as _;

    use super::*;
    use crate::chat::{Request as ChatRequest, Response as ChatResponse};

    #[test]
    fn registration_get_session_request_as_chat_request() {
        let request: ChatRequest = RegistrationRequest {
            session_id: &SessionId::from_str("aaabbbcccdddeee").unwrap(),
            request: GetSession {},
        }
        .into();

        assert_eq!(
            request,
            ChatRequest {
                method: Method::GET,
                path: PathAndQuery::from_static("/v1/verification/session/aaabbbcccdddeee"),
                headers: HeaderMap::default(),
                body: None,
            }
        )
    }

    #[test]
    fn registration_update_session_request_as_chat_request() {
        let captcha_request: ChatRequest = RegistrationRequest {
            session_id: &SessionId::from_str("aaabbbcccdddeee").unwrap(),
            request: UpdateRegistrationSession {
                captcha: Some("captcha"),
                ..Default::default()
            },
        }
        .into();

        assert_eq!(
            captcha_request,
            ChatRequest {
                method: Method::PATCH,
                path: PathAndQuery::from_static("/v1/verification/session/aaabbbcccdddeee"),
                headers: HeaderMap::from_iter([CONTENT_TYPE_JSON]),
                body: Some(b"{\"captcha\":\"captcha\"}".as_slice().into())
            }
        );

        let captcha_request: ChatRequest = RegistrationRequest {
            session_id: &SessionId::from_str("aaabbbcccdddeee").unwrap(),
            request: UpdateRegistrationSession {
                push_token_type: Some(PushTokenType::Apn),
                ..Default::default()
            },
        }
        .into();

        assert_eq!(
            captcha_request,
            ChatRequest {
                method: Method::PATCH,
                path: PathAndQuery::from_static("/v1/verification/session/aaabbbcccdddeee"),
                headers: HeaderMap::from_iter([CONTENT_TYPE_JSON]),
                body: Some(b"{\"pushTokenType\":\"apn\"}".as_slice().into())
            }
        )
    }

    #[test]
    fn registration_request_verification_as_chat_request() {
        let captcha_request: ChatRequest = RegistrationRequest {
            session_id: &SessionId::from_str("aaabbbcccdddeee").unwrap(),
            request: RequestVerificationCode {
                transport: VerificationTransport::Sms,
                client: "client name",
            },
        }
        .into();

        assert_eq!(
            captcha_request,
            ChatRequest {
                method: Method::POST,
                path: PathAndQuery::from_static("/v1/verification/session/aaabbbcccdddeee/code"),
                headers: HeaderMap::from_iter([CONTENT_TYPE_JSON]),
                body: Some(
                    b"{\"transport\":\"sms\",\"client\":\"client name\"}"
                        .as_slice()
                        .into()
                )
            }
        );
    }

    #[test]
    fn registration_response_deserialize() {
        const RESPONSE_JSON: &str = r#"{
                "id": "fivesixseven",
                "allowedToRequestCode": true,
                "verified": true,
                "requestedInformation": ["pushChallenge", "captcha"]
            }"#;
        let response: RegistrationResponse = ChatResponse {
            status: StatusCode::OK,
            message: Some("OK".to_owned()),
            headers: HeaderMap::from_iter([CONTENT_TYPE_JSON]),
            body: Some(RESPONSE_JSON.as_bytes().into()),
        }
        .try_into()
        .unwrap();

        assert_eq!(
            response,
            RegistrationResponse {
                session_id: "fivesixseven".parse().unwrap(),
                session: RegistrationSession {
                    allowed_to_request_code: true,
                    verified: true,
                    next_sms: None,
                    next_call: None,
                    next_verification_attempt: None,
                    requested_information: HashSet::from([
                        RequestedInformation::Captcha,
                        RequestedInformation::PushChallenge
                    ]),
                }
            }
        );
    }
}
