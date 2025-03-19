use std::collections::HashSet;
use std::time::Duration;

use http::uri::PathAndQuery;
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use libsignal_net_infra::errors::{LogSafeDisplay, RetryLater};
use libsignal_net_infra::extract_retry_later;

use crate::registration::SessionId;

const CONTENT_TYPE_JSON: (HeaderName, HeaderValue) = (
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

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize)]
#[cfg_attr(test, derive(serde::Serialize))]
#[serde(rename_all = "camelCase", default)]
pub struct RegistrationSession {
    pub allowed_to_request_code: bool,
    pub verified: bool,
    #[serde(deserialize_with = "optional_duration_seconds")]
    pub next_sms: Option<Duration>,
    #[serde(deserialize_with = "optional_duration_seconds")]
    pub next_call: Option<Duration>,
    #[serde(deserialize_with = "optional_duration_seconds")]
    pub next_verification_attempt: Option<Duration>,
    pub requested_information: HashSet<RequestedInformation>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(test, derive(serde::Serialize))]
pub enum RequestedInformation {
    PushChallenge,
    Captcha,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PushTokenType {
    Apn,
    Fcm,
}

pub(super) struct RegistrationRequest<'s, R> {
    pub(super) session_id: &'s SessionId,
    pub(super) request: R,
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
pub(super) enum ResponseError {
    /// {0}
    RetryLater(RetryLater),
    /// unexpected content-type {0:?}
    UnexpectedContentType(Option<HeaderValue>),
    /// unexpected response status {0}
    UnrecognizedStatus(StatusCode),
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
            if let Some(retry_later) = (status == StatusCode::TOO_MANY_REQUESTS)
                .then(|| extract_retry_later(&headers))
                .flatten()
            {
                return Err(ResponseError::RetryLater(retry_later));
            }
            return Err(ResponseError::UnrecognizedStatus(status));
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

impl<'s> From<RegistrationRequest<'s, GetSession>> for crate::chat::Request {
    fn from(value: RegistrationRequest<'s, GetSession>) -> Self {
        let RegistrationRequest {
            session_id,
            request: GetSession {},
        } = value;

        let path = format!(
            "{VERIFICATION_SESSION_PATH_PREFIX}/{}",
            session_id.as_url_path_segment()
        )
        .parse()
        .unwrap();

        Self {
            method: Method::GET,
            headers: HeaderMap::default(),
            path,
            body: None,
        }
    }
}

fn optional_duration_seconds<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    serde::Deserialize::deserialize(deserializer)
        .map(|value: Option<u32>| value.map(Into::into).map(Duration::from_secs))
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
    fn registration_request_as_chat_request() {
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
