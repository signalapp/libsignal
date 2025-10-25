//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;
use std::time::Duration;

use http::uri::InvalidUri;
use http::{HeaderName, HeaderValue, StatusCode};
use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_bridge_types::net::chat::*;
use libsignal_bridge_types::net::{ConnectionManager, TokioAsyncContext};
use libsignal_bridge_types::support::AsType;
use libsignal_core::ServiceId;
use libsignal_net::auth::Auth;
use libsignal_net::chat::{self, ConnectError, LanguageList, Response as ChatResponse, SendError};
use libsignal_net_chat::api::RequestError;
use libsignal_net_chat::api::messages::{
    MultiRecipientMessageResponse, MultiRecipientSendAuthorization, MultiRecipientSendFailure,
    UnauthenticatedChatApi as _,
};
use libsignal_net_chat::api::usernames::UnauthenticatedChatApi as _;
use libsignal_protocol::Timestamp;
use uuid::Uuid;

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
    connection_info.transport_info.local_addr.port()
}

#[bridge_fn(jni = false)]
fn ChatConnectionInfo_ip_version(connection_info: &ChatConnectionInfo) -> u8 {
    connection_info.transport_info.ip_version() as u8
}

#[bridge_fn(jni = false)]
fn ChatConnectionInfo_description(connection_info: &ChatConnectionInfo) -> String {
    connection_info.to_string()
}

#[bridge_io(TokioAsyncContext)]
async fn UnauthenticatedChatConnection_connect(
    connection_manager: &ConnectionManager,
    languages: LanguageList,
) -> Result<UnauthenticatedChatConnection, ConnectError> {
    UnauthenticatedChatConnection::connect(connection_manager, languages).await
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
) -> Result<ChatResponse, SendError> {
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
async fn UnauthenticatedChatConnection_look_up_username_hash(
    chat: &UnauthenticatedChatConnection,
    hash: Box<[u8]>,
) -> Result<Option<Uuid>, RequestError<Infallible>> {
    Ok(chat
        .as_typed(|chat| chat.look_up_username_hash(&hash))
        .await?
        .map(|aci| aci.into()))
}

#[bridge_io(TokioAsyncContext)]
async fn UnauthenticatedChatConnection_look_up_username_link(
    chat: &UnauthenticatedChatConnection,
    uuid: Uuid,
    entropy: Box<[u8]>,
) -> Result<Option<(String, [u8; 32])>, RequestError<::usernames::UsernameLinkError>> {
    let entropy = entropy[..].try_into().map_err(|_| {
        RequestError::Other(::usernames::UsernameLinkError::InvalidEntropyDataLength)
    })?;
    Ok(chat
        .as_typed(|chat| chat.look_up_username_link(uuid, &entropy))
        .await?
        .map(|username| {
            // Return both the username and the hash now; we already did the work of computing the
            // hash when validating the decrypted username.
            (username.to_string(), username.hash())
        }))
}

#[bridge_io(TokioAsyncContext)]
async fn UnauthenticatedChatConnection_send_multi_recipient_message(
    chat: &UnauthenticatedChatConnection,
    payload: Box<[u8]>,
    timestamp: Timestamp,
    auth: MultiRecipientSendAuthorization,
    online_only: bool,
    is_urgent: bool,
) -> Result<Vec<ServiceId>, RequestError<MultiRecipientSendFailure>> {
    let MultiRecipientMessageResponse { unregistered_ids } = chat
        .as_typed(|chat| {
            chat.send_multi_recipient_message(
                payload.into(),
                timestamp,
                auth,
                online_only,
                is_urgent,
            )
        })
        .await?;
    Ok(unregistered_ids)
}

#[bridge_io(TokioAsyncContext)]
async fn AuthenticatedChatConnection_preconnect(
    connection_manager: &ConnectionManager,
) -> Result<(), ConnectError> {
    AuthenticatedChatConnection::preconnect(connection_manager).await
}

#[bridge_io(TokioAsyncContext)]
async fn AuthenticatedChatConnection_connect(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
    receive_stories: bool,
    languages: LanguageList,
) -> Result<AuthenticatedChatConnection, ConnectError> {
    AuthenticatedChatConnection::connect(
        connection_manager,
        Auth { username, password },
        receive_stories,
        languages,
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
) -> Result<ChatResponse, SendError> {
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
fn ServerMessageAck_Send(ack: &ServerMessageAck) -> Result<(), SendError> {
    let sender = ack.take().expect("a message is only acked once");
    sender(StatusCode::OK)
}

#[bridge_fn(jni = false, ffi = false)]
fn ServerMessageAck_SendStatus(
    ack: &ServerMessageAck,
    status: AsType<HttpStatus, u16>,
) -> Result<(), SendError> {
    let sender = ack.take().expect("a message is only acked once");
    sender(status.into_inner().into())
}
