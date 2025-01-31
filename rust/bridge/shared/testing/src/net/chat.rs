//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::Duration;

use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use libsignal_bridge_macros::*;
use libsignal_bridge_types::net::chat::{
    AuthChat, AuthenticatedChatConnection, ChatListener, HttpRequest, ResponseAndDebugInfo,
};
use libsignal_bridge_types::net::TokioAsyncContext;
use libsignal_net::chat::fake::FakeChatRemote;
use libsignal_net::chat::{
    self, ChatServiceError, DebugInfo as ChatServiceDebugInfo, Response as ChatResponse,
};
use libsignal_net::infra::ws::WebSocketServiceError;
use libsignal_net::infra::IpType;

use crate::*;

pub struct FakeChatConnection {
    chat: std::sync::Mutex<Option<AuthenticatedChatConnection>>,
    remote_end: std::sync::Mutex<Option<FakeChatRemote>>,
}

pub struct FakeChatRemoteEnd(FakeChatRemote);

bridge_as_handle!(FakeChatConnection);
bridge_handle_fns!(FakeChatConnection, clone = false);
bridge_as_handle!(FakeChatRemoteEnd);
bridge_handle_fns!(FakeChatRemoteEnd, clone = false);

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
fn TESTING_FakeChatRemoteEnd_InjectConnectionInterrupted(chat: &FakeChatRemoteEnd) {
    chat.0
        .send_close(Some(1008 /* Policy Violation */))
        .expect("chat task finished")
}

#[bridge_fn]
fn TESTING_ChatServiceResponseConvert(
    body_present: bool,
) -> Result<ChatResponse, ChatServiceError> {
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
fn TESTING_ChatServiceDebugInfoConvert() -> Result<ChatServiceDebugInfo, ChatServiceError> {
    Ok(ChatServiceDebugInfo {
        ip_type: Some(IpType::V4),
        duration: Duration::from_millis(200),
        connection_info: "connection_info".to_string(),
    })
}

#[bridge_fn]
fn TESTING_ChatServiceResponseAndDebugInfoConvert() -> Result<ResponseAndDebugInfo, ChatServiceError>
{
    Ok(ResponseAndDebugInfo {
        response: TESTING_ChatServiceResponseConvert(true)?,
        debug_info: TESTING_ChatServiceDebugInfoConvert()?,
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

#[bridge_fn]
fn TESTING_ChatService_InjectRawServerRequest(chat: &AuthChat, bytes: &[u8]) {
    let request_proto = <chat::RequestProto as prost::Message>::decode(bytes)
        .expect("invalid protobuf cannot use this endpoint to test");
    chat.synthetic_request_tx
        .blocking_send(chat::ws::ServerEvent::fake(request_proto))
        .expect("not closed");
}

#[bridge_fn]
fn TESTING_ChatService_InjectConnectionInterrupted(chat: &AuthChat) {
    chat.synthetic_request_tx
        .blocking_send(chat::ws::ServerEvent::Stopped(ChatServiceError::WebSocket(
            WebSocketServiceError::ChannelClosed,
        )))
        .expect("not closed");
}

#[bridge_fn]
fn TESTING_ChatService_InjectIntentionalDisconnect(chat: &AuthChat) {
    chat.synthetic_request_tx
        .blocking_send(chat::ws::ServerEvent::Stopped(
            ChatServiceError::ServiceIntentionallyDisconnected,
        ))
        .expect("not closed");
}
