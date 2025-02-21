//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::Duration;

use http::uri::InvalidUri;
use http::{HeaderName, HeaderValue, StatusCode};
use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_bridge_types::net::chat::*;
use libsignal_bridge_types::net::{ConnectionManager, TokioAsyncContext};
use libsignal_bridge_types::support::AsType;
use libsignal_net::auth::Auth;
use libsignal_net::chat::{self, ChatServiceError, Response as ChatResponse};

use crate::support::*;
use crate::*;

bridge_handle_fns!(HttpRequest, clone = false);
bridge_handle_fns!(UnauthenticatedChatConnection, clone = false);
bridge_handle_fns!(AuthenticatedChatConnection, clone = false);

#[bridge_fn(ffi = false)]
fn HttpRequest_new(
    method: AsType<HttpMethod, String>,
    path: String,
    body_as_slice: Option<&[u8]>,
) -> Result<HttpRequest, InvalidUri> {
    HttpRequest::new(method.into_inner(), path, body_as_slice)
}

#[bridge_fn(jni = false, node = false)]
fn HttpRequest_new_with_body(
    method: AsType<HttpMethod, String>,
    path: String,
    body_as_slice: &[u8],
) -> Result<HttpRequest, InvalidUri> {
    HttpRequest::new(method.into_inner(), path, Some(body_as_slice))
}

#[bridge_fn(jni = false, node = false)]
fn HttpRequest_new_without_body(
    method: AsType<HttpMethod, String>,
    path: String,
) -> Result<HttpRequest, InvalidUri> {
    HttpRequest::new(method.into_inner(), path, None)
}

#[bridge_fn]
fn HttpRequest_add_header(
    request: &HttpRequest,
    name: AsType<HeaderName, String>,
    value: AsType<HeaderValue, String>,
) {
    request.add_header(name.into_inner(), value.into_inner())
}

#[bridge_fn(jni = false)]
fn ChatConnectionInfo_local_port(connection_info: &ChatConnectionInfo) -> u16 {
    connection_info.transport_info.local_port
}

#[bridge_fn(jni = false)]
fn ChatConnectionInfo_ip_version(connection_info: &ChatConnectionInfo) -> u8 {
    connection_info.transport_info.ip_version as u8
}

#[bridge_fn(jni = false)]
fn ChatConnectionInfo_description(connection_info: &ChatConnectionInfo) -> String {
    connection_info.to_string()
}

#[bridge_io(TokioAsyncContext)]
async fn UnauthenticatedChatConnection_connect(
    connection_manager: &ConnectionManager,
) -> Result<UnauthenticatedChatConnection, ChatServiceError> {
    UnauthenticatedChatConnection::connect(connection_manager).await
}

#[bridge_fn]
fn UnauthenticatedChatConnection_init_listener(
    chat: &UnauthenticatedChatConnection,
    listener: Box<dyn ChatListener>,
) {
    chat.init_listener(listener)
}

#[bridge_io(TokioAsyncContext)]
async fn UnauthenticatedChatConnection_send(
    chat: &UnauthenticatedChatConnection,
    http_request: &HttpRequest,
    timeout_millis: u32,
) -> Result<ChatResponse, ChatServiceError> {
    let headers = http_request.headers.lock().expect("not poisoned").clone();
    let request = chat::Request {
        method: http_request.method.clone(),
        path: http_request.path.clone(),
        headers,
        body: http_request.body.clone(),
    };
    chat.send(request, Duration::from_millis(timeout_millis.into()))
        .await
}

#[bridge_io(TokioAsyncContext)]
async fn UnauthenticatedChatConnection_disconnect(chat: &UnauthenticatedChatConnection) {
    chat.disconnect().await
}

#[bridge_fn]
fn UnauthenticatedChatConnection_info(chat: &UnauthenticatedChatConnection) -> ChatConnectionInfo {
    chat.info()
}

#[bridge_io(TokioAsyncContext)]
async fn AuthenticatedChatConnection_connect(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
    receive_stories: bool,
) -> Result<AuthenticatedChatConnection, ChatServiceError> {
    AuthenticatedChatConnection::connect(
        connection_manager,
        Auth { username, password },
        receive_stories,
    )
    .await
}

#[bridge_fn]
fn AuthenticatedChatConnection_init_listener(
    chat: &AuthenticatedChatConnection,
    listener: Box<dyn ChatListener>,
) {
    chat.init_listener(listener)
}

#[bridge_io(TokioAsyncContext)]
async fn AuthenticatedChatConnection_send(
    chat: &AuthenticatedChatConnection,
    http_request: &HttpRequest,
    timeout_millis: u32,
) -> Result<ChatResponse, ChatServiceError> {
    let headers = http_request.headers.lock().expect("not poisoned").clone();
    let request = chat::Request {
        method: http_request.method.clone(),
        path: http_request.path.clone(),
        headers,
        body: http_request.body.clone(),
    };
    chat.send(request, Duration::from_millis(timeout_millis.into()))
        .await
}

#[bridge_io(TokioAsyncContext)]
async fn AuthenticatedChatConnection_disconnect(chat: &AuthenticatedChatConnection) {
    chat.disconnect().await
}

#[bridge_fn(jni = false)]
fn AuthenticatedChatConnection_info(chat: &AuthenticatedChatConnection) -> ChatConnectionInfo {
    chat.info()
}

bridge_handle_fns!(ServerMessageAck, clone = false);

#[bridge_fn(node = false)]
fn ServerMessageAck_Send(ack: &ServerMessageAck) -> Result<(), ChatServiceError> {
    let sender = ack.take().expect("a message is only acked once");
    sender(StatusCode::OK)
}

#[bridge_fn(jni = false, ffi = false)]
fn ServerMessageAck_SendStatus(
    ack: &ServerMessageAck,
    status: AsType<HttpStatus, u16>,
) -> Result<(), ChatServiceError> {
    let sender = ack.take().expect("a message is only acked once");
    sender(status.into_inner().into())
}
