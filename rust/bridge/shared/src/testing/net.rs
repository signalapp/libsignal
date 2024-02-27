//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use libsignal_bridge_macros::*;
use libsignal_net::cdsi::{LookupError, LookupResponse, LookupResponseEntry, E164};
use libsignal_net::chat::{DebugInfo, IpType, Response};
use libsignal_net::infra::errors::NetError;
use libsignal_protocol::{Aci, Pni};
use nonzero_ext::nonzero;
use uuid::Uuid;

use crate::net::{HttpRequest, TokioAsyncContext};
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

#[bridge_fn]
fn TESTING_CdsiLookupErrorConvert() -> Result<(), LookupError> {
    Err(LookupError::ParseError)
}

#[bridge_fn(ffi = false, jni = false)]
fn TESTING_ChatServiceErrorConvert() -> Result<(), NetError> {
    Err(NetError::Timeout)
}

#[bridge_fn(ffi = false, jni = false)]
fn TESTING_ChatServiceResponseConvert(body_present: bool) -> Result<Response, NetError> {
    let body = match body_present {
        true => Some(b"content".to_vec().into_boxed_slice()),
        false => None,
    };
    let mut headers = HeaderMap::new();
    headers.append(http::header::USER_AGENT, HeaderValue::from_static("test"));
    headers.append(http::header::FORWARDED, HeaderValue::from_static("1.1.1.1"));
    Ok(Response {
        status: StatusCode::OK,
        message: None,
        body,
        headers,
    })
}

#[bridge_fn(ffi = false, jni = false)]
fn TESTING_ChatServiceDebugInfoConvert() -> Result<DebugInfo, NetError> {
    Ok(DebugInfo {
        connection_reused: true,
        reconnect_count: 2,
        ip_type: IpType::V4,
    })
}

#[bridge_fn(ffi = false, jni = false)]
fn TESTING_ChatRequestGetMethod(request: &HttpRequest) -> String {
    request.method.to_string()
}

#[bridge_fn(ffi = false, jni = false)]
fn TESTING_ChatRequestGetPath(request: &HttpRequest) -> String {
    request.path.to_string()
}

#[bridge_fn(ffi = false, jni = false)]
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

#[bridge_fn(ffi = false, jni = false)]
fn TESTING_ChatRequestGetBody(request: &HttpRequest) -> Option<Vec<u8>> {
    request.body.clone().map(|b| b.to_vec())
}
