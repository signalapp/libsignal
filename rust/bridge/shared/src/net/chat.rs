//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future;
use std::time::Duration;

use http::uri::InvalidUri;
use http::{HeaderName, HeaderValue, StatusCode};
use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_bridge_types::net::chat::*;
use libsignal_bridge_types::net::{ConnectionManager, TokioAsyncContext};
use libsignal_bridge_types::support::AsType;
use libsignal_net::auth::Auth;
use libsignal_net::chat::{
    self, ChatServiceError, DebugInfo as ChatServiceDebugInfo, Request, Response as ChatResponse,
};
use libsignal_net::infra::ws::WebSocketServiceError;

use crate::support::*;
use crate::*;

bridge_handle_fns!(Chat, clone = false);
bridge_handle_fns!(HttpRequest, clone = false);

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

#[bridge_fn]
fn ChatService_new(
    connection_manager: &ConnectionManager,
    username: String,
    password: String,
    receive_stories: bool,
) -> Chat {
    Chat::new(
        connection_manager,
        Auth { username, password },
        receive_stories,
    )
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_disconnect(chat: &Chat) {
    chat.service.disconnect().await
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_connect_unauth(chat: &Chat) -> Result<ChatServiceDebugInfo, ChatServiceError> {
    chat.service.connect_unauthenticated().await
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_connect_auth(chat: &Chat) -> Result<ChatServiceDebugInfo, ChatServiceError> {
    chat.service.connect_authenticated().await
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_unauth_send(
    chat: &Chat,
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
    chat.service
        .send_unauthenticated(request, Duration::from_millis(timeout_millis.into()))
        .await
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_unauth_send_and_debug(
    chat: &Chat,
    http_request: &HttpRequest,
    timeout_millis: u32,
) -> Result<ResponseAndDebugInfo, ChatServiceError> {
    let headers = http_request.headers.lock().expect("not poisoned").clone();
    let request = chat::Request {
        method: http_request.method.clone(),
        path: http_request.path.clone(),
        headers,
        body: http_request.body.clone(),
    };
    let (result, debug_info) = chat
        .service
        .send_unauthenticated_and_debug(request, Duration::from_millis(timeout_millis.into()))
        .await;

    result.map(|response| ResponseAndDebugInfo {
        response,
        debug_info,
    })
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_auth_send(
    chat: &Chat,
    http_request: &HttpRequest,
    timeout_millis: u32,
) -> Result<ChatResponse, ChatServiceError> {
    let headers = http_request.headers.lock().expect("not poisoned").clone();
    let request = Request {
        method: http_request.method.clone(),
        path: http_request.path.clone(),
        headers,
        body: http_request.body.clone(),
    };
    chat.service
        .send_authenticated(request, Duration::from_millis(timeout_millis.into()))
        .await
}

#[bridge_io(TokioAsyncContext)]
async fn ChatService_auth_send_and_debug(
    chat: &Chat,
    http_request: &HttpRequest,
    timeout_millis: u32,
) -> Result<ResponseAndDebugInfo, ChatServiceError> {
    let headers = http_request.headers.lock().expect("not poisoned").clone();
    let request = Request {
        method: http_request.method.clone(),
        path: http_request.path.clone(),
        headers,
        body: http_request.body.clone(),
    };
    let (result, debug_info) = chat
        .service
        .send_authenticated_and_debug(request, Duration::from_millis(timeout_millis.into()))
        .await;

    result.map(|response| ResponseAndDebugInfo {
        response,
        debug_info,
    })
}

#[bridge_fn(jni = false)]
fn ChatService_SetListenerAuth(
    runtime: &TokioAsyncContext,
    chat: &Chat,
    make_listener: Option<&dyn MakeChatListener>,
) {
    let Some(maker) = make_listener else {
        chat.clear_listener_auth();
        return;
    };

    let listener = maker.make_listener();

    chat.set_listener_auth(listener, runtime)
}

#[bridge_fn(jni = false, ffi = false)]
fn ChatService_SetListenerUnauth(
    runtime: &TokioAsyncContext,
    chat: &Chat,
    make_listener: Option<&dyn MakeChatListener>,
) {
    let Some(maker) = make_listener else {
        chat.clear_listener_unauth();
        return;
    };

    let listener = maker.make_listener();

    chat.set_listener_unauth(listener, runtime)
}

#[cfg(feature = "testing-fns")]
#[bridge_fn]
fn TESTING_ChatService_InjectRawServerRequest(chat: &Chat, bytes: &[u8]) {
    let request_proto = <chat::RequestProto as prost::Message>::decode(bytes)
        .expect("invalid protobuf cannot use this endpoint to test");
    chat.synthetic_request_tx
        .blocking_send(chat::ws::ServerEvent::fake(request_proto))
        .expect("not closed");
}

#[cfg(feature = "testing-fns")]
#[bridge_fn]
fn TESTING_ChatService_InjectConnectionInterrupted(chat: &Chat) {
    chat.synthetic_request_tx
        .blocking_send(chat::ws::ServerEvent::Stopped(ChatServiceError::WebSocket(
            WebSocketServiceError::ChannelClosed,
        )))
        .expect("not closed");
}

#[cfg(feature = "testing-fns")]
#[bridge_fn(jni = false, ffi = false)]
fn TESTING_ServerMessageAck_Create() -> ServerMessageAck {
    ServerMessageAck::new(Box::new(|_| Box::pin(future::ready(Ok(())))))
}

bridge_handle_fns!(ServerMessageAck, clone = false);

#[bridge_io(TokioAsyncContext, node = false)]
async fn ServerMessageAck_Send(ack: &ServerMessageAck) -> Result<(), ChatServiceError> {
    let future = ack.take().expect("a message is only acked once");
    future(StatusCode::OK).await
}

#[bridge_io(TokioAsyncContext, jni = false, ffi = false)]
async fn ServerMessageAck_SendStatus(
    ack: &ServerMessageAck,
    status: AsType<HttpStatus, u16>,
) -> Result<(), ChatServiceError> {
    let future = ack.take().expect("a message is only acked once");
    future(status.into_inner().into()).await
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::net::{ConnectionManager, ConnectionManager_set_proxy, Environment};
    use assert_matches::assert_matches;
    use libsignal_net::chat::ChatServiceError;

    // Normally we would write this test in the app languages, but it depends on timeouts.
    // Using a paused tokio runtime auto-advances time when there's no other work to be done.
    #[tokio::test(start_paused = true)]
    async fn cannot_connect_through_invalid_proxy() {
        let cm = ConnectionManager::new(Environment::Staging, "test-user-agent".to_string());

        assert_matches!(
            ConnectionManager_set_proxy(&cm, "signalfoundation.org".to_string(), 0),
            Err(_)
        );
        assert_matches!(
            ConnectionManager_set_proxy(&cm, "signalfoundation.org".to_string(), 100_000),
            Err(_)
        );

        assert_matches!(
            ConnectionManager_set_proxy(&cm, "signalfoundation.org".to_string(), -1),
            Err(_)
        );

        let chat = ChatService_new(&cm, "".to_string(), "".to_string(), false);
        assert_matches!(
            ChatService_connect_unauth(&chat).await,
            Err(ChatServiceError::AllConnectionRoutesFailed { .. })
        );
    }
}
