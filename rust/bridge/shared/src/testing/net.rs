//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::str::FromStr;
use std::time::Duration;

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use libsignal_bridge_macros::*;
use libsignal_net::cdsi::{LookupError, LookupResponse, LookupResponseEntry, E164};
use libsignal_net::chat::{ChatServiceError, DebugInfo, Response};
use libsignal_net::infra::IpType;
use libsignal_protocol::{Aci, Pni};
use nonzero_ext::nonzero;
use uuid::Uuid;

use crate::net::{HttpRequest, ResponseAndDebugInfo, TokioAsyncContext};
use crate::support::*;
use crate::*;

#[bridge_io(TokioAsyncContext)]
async fn TESTING_CdsiLookupResponseConvert() -> LookupResponse {
    const E164_BOTH: E164 = E164::new(nonzero!(18005551011u64));
    const E164_PNI: E164 = E164::new(nonzero!(18005551012u64));
    const ACI_UUID: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";
    const PNI_UUID: &str = "796abedb-ca4e-4f18-8803-1fde5b921f9f";
    const DEBUG_PERMITS_USED: i32 = 123;

    let aci = Aci::from(Uuid::parse_str(ACI_UUID).expect("is valid"));
    let pni = Pni::from(Uuid::parse_str(PNI_UUID).expect("is valid"));

    LookupResponse {
        records: vec![
            LookupResponseEntry {
                e164: E164_BOTH,
                aci: Some(aci),
                pni: Some(pni),
            },
            LookupResponseEntry {
                e164: E164_PNI,
                pni: Some(pni),
                aci: None,
            },
        ],
        debug_permits_used: DEBUG_PERMITS_USED,
    }
}

#[repr(u8)]
#[derive(Copy, Clone, strum::EnumString)]
enum TestingCdsiLookupError {
    Protocol,
    AttestationDataError,
    InvalidResponse,
    RetryAfter42Seconds,
    InvalidToken,
    InvalidArgument,
    Parse,
    ConnectDnsFailed,
    WebSocketIdleTooLong,
    Timeout,
    ServerCrashed,
}

const _: () = {
    /// This code isn't ever executed. It exists so that when new cases are
    /// added to `LookupError`, this will fail to compile until corresponding
    /// cases are added to `TestingCdsiLookupError`
    #[allow(unused)]
    fn match_on_lookup_error(value: &'static LookupError) -> TestingCdsiLookupError {
        match value {
            LookupError::Protocol => TestingCdsiLookupError::Protocol,
            LookupError::AttestationError(_) => TestingCdsiLookupError::AttestationDataError,
            LookupError::InvalidResponse => TestingCdsiLookupError::InvalidResponse,
            LookupError::RateLimited {
                retry_after_seconds: _,
            } => TestingCdsiLookupError::RetryAfter42Seconds,
            LookupError::InvalidToken => TestingCdsiLookupError::InvalidToken,
            LookupError::InvalidArgument { server_reason: _ } => {
                TestingCdsiLookupError::InvalidArgument
            }
            LookupError::ParseError => TestingCdsiLookupError::Parse,
            LookupError::ConnectTransport(_) => TestingCdsiLookupError::ConnectDnsFailed,
            LookupError::WebSocket(_) => TestingCdsiLookupError::WebSocketIdleTooLong,
            LookupError::Timeout => TestingCdsiLookupError::Timeout,
            LookupError::Server { reason } => TestingCdsiLookupError::ServerCrashed,
        }
    }
};

impl TryFrom<String> for TestingCdsiLookupError {
    type Error = <Self as FromStr>::Err;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        FromStr::from_str(&value)
    }
}

/// Return an error matching the requested description.
#[bridge_fn]
fn TESTING_CdsiLookupErrorConvert(
    // The stringly-typed API makes the call sites more self-explanatory.
    error_description: AsType<TestingCdsiLookupError, String>,
) -> Result<(), LookupError> {
    Err(match error_description.into_inner() {
        TestingCdsiLookupError::Protocol => LookupError::Protocol,
        TestingCdsiLookupError::AttestationDataError => {
            LookupError::AttestationError(attest::enclave::Error::AttestationDataError {
                reason: "fake reason".into(),
            })
        }
        TestingCdsiLookupError::InvalidResponse => LookupError::InvalidResponse,
        TestingCdsiLookupError::RetryAfter42Seconds => LookupError::RateLimited {
            retry_after_seconds: 42,
        },
        TestingCdsiLookupError::InvalidToken => LookupError::InvalidToken,
        TestingCdsiLookupError::InvalidArgument => LookupError::InvalidArgument {
            server_reason: "fake reason".into(),
        },
        TestingCdsiLookupError::Parse => LookupError::ParseError,
        TestingCdsiLookupError::ConnectDnsFailed => LookupError::ConnectTransport(
            libsignal_net::infra::errors::TransportConnectError::DnsError,
        ),
        TestingCdsiLookupError::WebSocketIdleTooLong => LookupError::WebSocket(
            libsignal_net::infra::ws::WebSocketServiceError::ChannelIdleTooLong,
        ),
        TestingCdsiLookupError::Timeout => LookupError::Timeout,
        TestingCdsiLookupError::ServerCrashed => LookupError::Server { reason: "crashed" },
    })
}

#[bridge_fn(ffi = false)]
fn TESTING_ChatServiceErrorConvert() -> Result<(), ChatServiceError> {
    Err(ChatServiceError::Timeout)
}

#[bridge_fn(ffi = false)]
fn TESTING_ChatServiceResponseConvert(body_present: bool) -> Result<Response, ChatServiceError> {
    let body = match body_present {
        true => Some(b"content".to_vec().into_boxed_slice()),
        false => None,
    };
    let mut headers = HeaderMap::new();
    headers.append(http::header::USER_AGENT, HeaderValue::from_static("test"));
    headers.append(http::header::FORWARDED, HeaderValue::from_static("1.1.1.1"));
    Ok(Response {
        status: StatusCode::OK,
        message: Some("OK".to_string()),
        body,
        headers,
    })
}

#[bridge_fn(ffi = false)]
fn TESTING_ChatServiceDebugInfoConvert() -> Result<DebugInfo, ChatServiceError> {
    Ok(DebugInfo {
        connection_reused: true,
        reconnect_count: 2,
        ip_type: IpType::V4,
        duration: Duration::from_millis(200),
        connection_info: "connection_info".to_string(),
    })
}

#[bridge_fn(ffi = false)]
fn TESTING_ChatServiceResponseAndDebugInfoConvert() -> Result<ResponseAndDebugInfo, ChatServiceError>
{
    Ok(ResponseAndDebugInfo {
        response: TESTING_ChatServiceResponseConvert(true)?,
        debug_info: TESTING_ChatServiceDebugInfoConvert()?,
    })
}

#[bridge_fn(ffi = false)]
fn TESTING_ChatRequestGetMethod(request: &HttpRequest) -> String {
    request.method.to_string()
}

#[bridge_fn(ffi = false)]
fn TESTING_ChatRequestGetPath(request: &HttpRequest) -> String {
    request.path.to_string()
}

#[bridge_fn(ffi = false)]
fn TESTING_ChatRequestGetHeaderValue(request: &HttpRequest, header_name: String) -> String {
    request
        .headers
        .lock()
        .expect("not poisoned")
        .get(HeaderName::try_from(header_name).expect("valid header name"))
        .expect("header value present")
        .to_str()
        .expect("value is a string")
        .to_string()
}

#[bridge_fn(ffi = false)]
fn TESTING_ChatRequestGetBody(request: &HttpRequest) -> Option<Vec<u8>> {
    request.body.clone().map(|b| b.to_vec())
}
