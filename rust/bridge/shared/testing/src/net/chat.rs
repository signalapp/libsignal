//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use libsignal_bridge_macros::*;
use libsignal_bridge_types::net::TokioAsyncContext;
use libsignal_bridge_types::net::chat::{
    AuthenticatedChatConnection, ChatListener, HttpRequest, UnauthenticatedChatConnection,
};
use libsignal_net::chat::fake::FakeChatRemote;
use libsignal_net::chat::{
    ConnectError, RequestProto, Response as ChatResponse, ResponseProto, SendError,
};
use libsignal_net::infra::errors::RetryLater;

use crate::net::make_error_testing_enum;
use crate::*;

pub struct FakeChatConnection {
    chat: std::sync::Mutex<Option<libsignal_bridge_types::net::chat::FakeChatConnection>>,
    remote_end: std::sync::Mutex<Option<FakeChatRemote>>,
}

pub struct FakeChatServer {
    pub(crate) tx: tokio::sync::mpsc::UnboundedSender<FakeChatRemote>,
    remote_end: tokio::sync::Mutex<tokio::sync::mpsc::UnboundedReceiver<FakeChatRemote>>,
}

pub struct FakeChatRemoteEnd(FakeChatRemote);

pub struct FakeChatResponse(ResponseProto);

bridge_as_handle!(FakeChatConnection);
bridge_handle_fns!(FakeChatConnection, clone = false);
bridge_as_handle!(FakeChatRemoteEnd);
bridge_handle_fns!(FakeChatRemoteEnd, clone = false);
bridge_as_handle!(FakeChatServer);
bridge_handle_fns!(FakeChatServer, clone = false);
bridge_as_handle!(FakeChatResponse);
bridge_handle_fns!(FakeChatResponse, clone = false);

impl std::panic::RefUnwindSafe for FakeChatServer {}
impl std::panic::RefUnwindSafe for FakeChatConnection {}
impl std::panic::RefUnwindSafe for FakeChatRemoteEnd {}

#[bridge_fn]
fn TESTING_FakeChatServer_Create() -> FakeChatServer {
    let (fake_chat_remote_tx, fake_chat_remote_rx) = tokio::sync::mpsc::unbounded_channel();

    FakeChatServer {
        tx: fake_chat_remote_tx,
        remote_end: fake_chat_remote_rx.into(),
    }
}

#[bridge_io(TokioAsyncContext)]
async fn TESTING_FakeChatServer_GetNextRemote(server: &FakeChatServer) -> FakeChatRemoteEnd {
    let remote = server
        .remote_end
        .lock()
        .await
        .recv()
        .await
        .expect("server still live");
    FakeChatRemoteEnd(remote)
}

#[bridge_fn]
fn TESTING_FakeChatConnection_Create(
    tokio: &TokioAsyncContext,
    listener: Box<dyn ChatListener>,
    alerts_joined_by_newlines: String,
) -> FakeChatConnection {
    // "".split_terminator(...) produces [], while normal split() produces [""].
    let alerts = alerts_joined_by_newlines.split_terminator('\n');
    let (chat, remote) = libsignal_bridge_types::net::chat::FakeChatConnection::new(
        tokio.handle(),
        listener,
        alerts,
    );
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
    chat.expect("can't take chat twice").into_authenticated()
}

#[bridge_fn]
fn TESTING_FakeChatConnection_TakeUnauthenticatedChat(
    chat: &FakeChatConnection,
) -> UnauthenticatedChatConnection {
    let chat = chat.chat.lock().expect("not poisoned").take();
    chat.expect("can't take chat twice").into_unauthenticated()
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
fn TESTING_FakeChatRemoteEnd_SendServerResponse(
    chat: &FakeChatRemoteEnd,
    response: &FakeChatResponse,
) {
    let FakeChatResponse(proto) = response;
    chat.0
        .send_response(proto.clone())
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
) -> Option<(HttpRequest, u64)> {
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
        body,
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

    Some((http_request, id.unwrap()))
}

#[bridge_fn]
fn TESTING_ChatResponseConvert(body_present: bool) -> ChatResponse {
    let body = match body_present {
        true => Some(Bytes::from_static(b"content")),
        false => None,
    };
    let mut headers = HeaderMap::new();
    headers.append(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.append(http::header::FORWARDED, HeaderValue::from_static("1.1.1.1"));
    ChatResponse {
        status: StatusCode::OK,
        message: Some("OK".to_string()),
        body,
        headers,
    }
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
fn TESTING_ChatRequestGetHeaderNames(request: &HttpRequest) -> Box<[String]> {
    request
        .headers
        .lock()
        .expect("not poisoned")
        .keys()
        .map(ToString::to_string)
        .collect()
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
fn TESTING_ChatRequestGetBody(request: &HttpRequest) -> &[u8] {
    request.body.as_deref().unwrap_or_default()
}

#[bridge_fn]
fn TESTING_FakeChatResponse_Create(
    id: u64,
    status: u16,
    message: String,
    headers: Box<[String]>,
    body: Option<Box<[u8]>>,
) -> FakeChatResponse {
    FakeChatResponse(ResponseProto {
        id: Some(id),
        status: Some(status.into()),
        message: Some(message),
        headers: headers.into(),
        body: body.map(Into::into),
    })
}

make_error_testing_enum! {
    enum TestingChatConnectError for ConnectError {
        WebSocket => WebSocketConnectionFailed,
        AppExpired => AppExpired,
        DeviceDeregistered => DeviceDeregistered,
        Timeout => Timeout,
        AllAttemptsFailed => AllAttemptsFailed,
        InvalidConnectionConfiguration => InvalidConnectionConfiguration,
        RetryLater => RetryAfter42Seconds,
    }
}

#[bridge_fn]
fn TESTING_ChatConnectErrorConvert(
    // The stringly-typed API makes the call sites more self-explanatory.
    error_description: AsType<TestingChatConnectError, String>,
) -> Result<(), ConnectError> {
    Err(match error_description.into_inner() {
        TestingChatConnectError::WebSocketConnectionFailed => {
            ConnectError::WebSocket(libsignal_net::infra::ws::WebSocketConnectError::Transport(
                libsignal_net::infra::errors::TransportConnectError::TcpConnectionFailed,
            ))
        }
        TestingChatConnectError::AppExpired => ConnectError::AppExpired,
        TestingChatConnectError::DeviceDeregistered => ConnectError::DeviceDeregistered,
        TestingChatConnectError::Timeout => ConnectError::Timeout,
        TestingChatConnectError::AllAttemptsFailed => ConnectError::AllAttemptsFailed,
        TestingChatConnectError::InvalidConnectionConfiguration => {
            ConnectError::InvalidConnectionConfiguration
        }
        TestingChatConnectError::RetryAfter42Seconds => ConnectError::RetryLater(RetryLater {
            retry_after_seconds: 42,
        }),
    })
}

make_error_testing_enum! {
    enum TestingChatSendError for SendError {
        RequestTimedOut => RequestTimedOut,
        Disconnected => Disconnected,
        ConnectionInvalidated => ConnectionInvalidated,
        ConnectedElsewhere => ConnectedElsewhere,
        WebSocket => WebSocketConnectionReset,
        IncomingDataInvalid => IncomingDataInvalid,
        RequestHasInvalidHeader => RequestHasInvalidHeader,
    }
}

#[bridge_fn]
fn TESTING_ChatSendErrorConvert(
    // The stringly-typed API makes the call sites more self-explanatory.
    error_description: AsType<TestingChatSendError, String>,
) -> Result<(), SendError> {
    Err(match error_description.into_inner() {
        TestingChatSendError::RequestTimedOut => SendError::RequestTimedOut,
        TestingChatSendError::Disconnected => SendError::Disconnected,
        TestingChatSendError::ConnectionInvalidated => SendError::ConnectionInvalidated,
        TestingChatSendError::ConnectedElsewhere => SendError::ConnectedElsewhere,
        TestingChatSendError::WebSocketConnectionReset => {
            SendError::WebSocket(libsignal_net::infra::ws::WebSocketError::Io(
                std::io::ErrorKind::ConnectionReset.into(),
            ))
        }
        TestingChatSendError::IncomingDataInvalid => SendError::IncomingDataInvalid,
        TestingChatSendError::RequestHasInvalidHeader => SendError::RequestHasInvalidHeader,
    })
}
