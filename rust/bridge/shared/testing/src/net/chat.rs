//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use libsignal_bridge_macros::*;
use libsignal_bridge_types::net::chat::{AuthenticatedChatConnection, ChatListener, HttpRequest};
use libsignal_bridge_types::net::TokioAsyncContext;
use libsignal_net::chat::fake::FakeChatRemote;
use libsignal_net::chat::{ChatServiceError, RequestProto, Response as ChatResponse};

use crate::*;

pub struct FakeChatConnection {
    chat: std::sync::Mutex<Option<AuthenticatedChatConnection>>,
    remote_end: std::sync::Mutex<Option<FakeChatRemote>>,
}

pub struct FakeChatRemoteEnd(FakeChatRemote);

pub struct FakeChatSentRequest {
    // Hold as an Option so that the value can be taken.
    http: Option<HttpRequest>,
    id: u64,
}

bridge_as_handle!(FakeChatConnection);
bridge_handle_fns!(FakeChatConnection, clone = false);
bridge_as_handle!(FakeChatRemoteEnd);
bridge_handle_fns!(FakeChatRemoteEnd, clone = false);
bridge_as_handle!(FakeChatSentRequest, mut = true);
bridge_handle_fns!(FakeChatSentRequest, clone = false);

impl std::panic::RefUnwindSafe for FakeChatConnection {}
impl std::panic::RefUnwindSafe for FakeChatRemoteEnd {}

#[bridge_fn]
fn TESTING_FakeChatConnection_Create(
    tokio: &TokioAsyncContext,
    listener: Box<dyn ChatListener>,
) -> FakeChatConnection {
    let (chat, remote) = AuthenticatedChatConnection::new_fake(tokio.handle(), listener);
    FakeChatConnection {
        chat: Some(chat).into(),
        remote_end: Some(remote).into(),
    }
}

#[bridge_fn]
fn TESTING_FakeChatConnection_TakeAuthenticatedChat(
    chat: &FakeChatConnection,
) -> AuthenticatedChatConnection {
    let chat = chat.chat.lock().expect("not poisoned").take();
    chat.expect("can't take chat twice")
}

#[bridge_fn]
fn TESTING_FakeChatConnection_TakeRemote(chat: &FakeChatConnection) -> FakeChatRemoteEnd {
    let chat = chat.remote_end.lock().expect("not poisoned").take();
    FakeChatRemoteEnd(chat.expect("can't take chat twice"))
}

#[bridge_fn]
fn TESTING_FakeChatRemoteEnd_SendRawServerRequest(chat: &FakeChatRemoteEnd, bytes: &[u8]) {
    chat.0
        .send_request(prost::Message::decode(bytes).expect("invalid Request proto"))
        .expect("chat task finished")
}

#[bridge_fn]
fn TESTING_FakeChatRemoteEnd_SendRawServerResponse(chat: &FakeChatRemoteEnd, bytes: &[u8]) {
    chat.0
        .send_response(prost::Message::decode(bytes).expect("invalid Response proto"))
        .expect("chat task finished")
}

#[bridge_fn]
fn TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted(chat: &FakeChatRemoteEnd) {
    chat.0
        .send_close(Some(1008 /* Policy Violation */))
        .expect("chat task finished")
}

#[bridge_io(TokioAsyncContext)]
async fn TESTING_FakeChatRemoteEnd_ReceiveIncomingRequest(
    chat: &FakeChatRemoteEnd,
) -> Option<FakeChatSentRequest> {
    let request = chat
        .0
        .receive_request()
        .await
        .expect("message was invalid")?;
    let RequestProto {
        verb,
        path,
        body,
        headers,
        id,
    } = request;

    let http_request = HttpRequest {
        method: verb.unwrap().as_str().try_into().unwrap(),
        path: path.unwrap().try_into().unwrap(),
        body: body.map(Vec::into_boxed_slice),
        headers: headers
            .into_iter()
            .map(|header| {
                let (name, value) = header.split_once(":").expect("previously parsed");
                (
                    name.trim().try_into().unwrap(),
                    value.trim().try_into().unwrap(),
                )
            })
            .collect::<HeaderMap>()
            .into(),
    };

    Some(FakeChatSentRequest {
        http: Some(http_request),
        id: id.unwrap(),
    })
}

#[bridge_fn]
fn TESTING_FakeChatSentRequest_TakeHttpRequest(request: &mut FakeChatSentRequest) -> HttpRequest {
    request.http.take().expect("not taken yet")
}

#[bridge_fn]
fn TESTING_FakeChatSentRequest_RequestId(request: &FakeChatSentRequest) -> u64 {
    request.id
}

#[bridge_fn]
fn TESTING_ChatResponseConvert(body_present: bool) -> Result<ChatResponse, ChatServiceError> {
    let body = match body_present {
        true => Some(b"content".to_vec().into_boxed_slice()),
        false => None,
    };
    let mut headers = HeaderMap::new();
    headers.append(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.append(http::header::FORWARDED, HeaderValue::from_static("1.1.1.1"));
    Ok(ChatResponse {
        status: StatusCode::OK,
        message: Some("OK".to_string()),
        body,
        headers,
    })
}

#[bridge_fn]
fn TESTING_ChatRequestGetMethod(request: &HttpRequest) -> String {
    request.method.to_string()
}

#[bridge_fn]
fn TESTING_ChatRequestGetPath(request: &HttpRequest) -> String {
    request.path.to_string()
}

#[bridge_fn]
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

#[bridge_fn]
fn TESTING_ChatRequestGetBody(request: &HttpRequest) -> Vec<u8> {
    request
        .body
        .clone()
        .map(|b| b.into_vec())
        .unwrap_or_default()
}
