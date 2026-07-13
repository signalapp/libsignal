//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use libsignal_bridge_types::net::TokioAsyncContext;
use libsignal_bridge_types::net::chat::{
    AuthenticatedChatConnection, BridgeCopyBackupMediaItem, ChatListener, HttpRequest,
    ProvisioningChatConnection, ProvisioningListener, UnauthenticatedChatConnection,
};
use libsignal_net::chat::fake::{BodyWithTrailers, FakeChatRemote};
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
    remote_end: AsyncMutex<tokio::sync::mpsc::UnboundedReceiver<FakeChatRemote>>,
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

// These aren't really guaranteed, but FakeChat* is only used for testing anyway.
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
    grpc_overrides_joined_by_newlines: String,
    alerts_joined_by_newlines: String,
) -> FakeChatConnection {
    // "".split_terminator(...) produces [], while normal split() produces [""].
    // Leaking is unfortunate, but more expedient than mapping to remote config keys or similar.
    let grpc_overrides = String::leak(grpc_overrides_joined_by_newlines).split_terminator('\n');
    let alerts = alerts_joined_by_newlines.split_terminator('\n');

    let (chat, remote) = libsignal_bridge_types::net::chat::FakeChatConnection::new(
        tokio.handle(),
        listener.into_event_listener(),
        grpc_overrides,
        alerts,
    );
    FakeChatConnection {
        chat: Some(chat).into(),
        remote_end: Some(remote).into(),
    }
}

#[bridge_fn]
fn TESTING_FakeChatConnection_CreateProvisioning(
    tokio: &TokioAsyncContext,
    listener: Box<dyn ProvisioningListener>,
) -> FakeChatConnection {
    let (chat, remote) = libsignal_bridge_types::net::chat::FakeChatConnection::new(
        tokio.handle(),
        listener.into_event_listener(),
        [],
        [],
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
fn TESTING_FakeChatConnection_TakeProvisioningChat(
    chat: &FakeChatConnection,
) -> ProvisioningChatConnection {
    let chat = chat.chat.lock().expect("not poisoned").take();
    chat.expect("can't take chat twice").into_provisioning()
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

#[bridge_io(TokioAsyncContext)]
async fn TESTING_FakeChatRemoteEnd_SendServerGrpcResponse(
    chat: &FakeChatRemoteEnd,
    response: &FakeChatResponse,
) {
    let FakeChatResponse(ResponseProto {
        id,
        status,
        message,
        headers,
        body,
    }) = response;

    assert!(
        message.as_deref().unwrap_or_default().is_empty(),
        "messages not supported for gRPC"
    );
    assert!(headers.is_empty(), "headers not yet implemented for gRPC");

    let body = BodyWithTrailers {
        data: body
            .as_ref()
            .map(|bytes| bytes.to_vec())
            .unwrap_or_default(),
        trailers: grpc_ok_trailers(),
    };

    let http_response = http::Response::builder()
        .status(u16::try_from(status.unwrap_or_default()).unwrap_or(u16::MAX))
        .body(body)
        .expect("valid");

    chat.0
        .grpc()
        .await
        .send_response(id.unwrap_or_default(), http_response)
        .expect("chat task finished");
}

#[bridge_io(TokioAsyncContext)]
async fn TESTING_FakeChatRemoteEnd_SendServerGrpcTestCaseResponse(
    chat: &FakeChatRemoteEnd,
    id: u64,
    response: &GrpcTestCaseBridgedResponse,
) {
    chat.0
        .grpc()
        .await
        .send_response(id, http::Response::new(response.0.clone()))
        .expect("chat task finished");
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

#[bridge_io(TokioAsyncContext)]
async fn TESTING_FakeChatRemoteEnd_ReceiveIncomingGrpcRequest(
    chat: &FakeChatRemoteEnd,
) -> Option<(HttpRequest, u64)> {
    let (id, request) = chat
        .0
        .grpc()
        .await
        .receive_request()
        .await
        .expect("message was invalid")?;
    let (
        http::request::Parts {
            method,
            uri,
            headers,
            ..
        },
        body,
    ) = request.into_parts();

    let http_request = HttpRequest {
        method,
        path: uri
            .into_parts()
            .path_and_query
            .expect("gRPC requests always have paths"),
        body: Some(body),
        headers: headers.into(),
    };

    Some((http_request, id))
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

#[bridge_fn]
fn TESTING_FakeChatRemoteEnd_NextGrpcMessage(input: &[u8], offset: u32) -> (u32, u32) {
    // Taking an offset avoids extra copies in the streaming input case.
    let input = &input[offset.try_into().expect("valid offset for buffer")..];
    let message_slice = libsignal_net_grpc::expect_next_grpc_message_for_testing(input);
    // We return a (start, end) pair for the app language to slice.
    // Unfortunately, getting that back out takes a bit of work.
    let message_offset = if let Some(first_elem) = message_slice.first() {
        // TODO: replace with slice::element_offset at MSRV 1.94.
        let first_elem = std::ptr::from_ref(first_elem);
        let slice_range = input.as_ptr_range();
        assert!(
            slice_range.contains(&first_elem),
            "result should be a subslice"
        );
        // Note: subtracting raw addresses only works because the elements are bytes.
        first_elem.addr() - slice_range.start.addr()
    } else {
        // If the message is empty, the header must have been the entire rest of the input.
        input.len()
    };
    let full_offset = offset + u32::try_from(message_offset).expect("input will never be >1GB");
    (
        full_offset,
        full_offset + u32::try_from(message_slice.len()).expect("input will never be >1GB"),
    )
}

#[bridge_fn]
fn TESTING_FakeChatRemoteEnd_GrpcFrameForMessageLength(len: u32) -> Vec<u8> {
    let mut result = Vec::with_capacity(5);
    result.push(0);
    result.extend_from_slice(&len.to_be_bytes());
    result
}

#[bridge_fn]
fn TESTING_FakeChatRemoteEnd_BinprotoToJson(name: String, input: &[u8]) -> String {
    libsignal_net_grpc::json::expect_binproto_to_json_by_name(&name, input)
}

#[bridge_fn]
fn TESTING_FakeChatRemoteEnd_JsonToBinproto(name: String, input: String) -> Vec<u8> {
    libsignal_net_grpc::json::expect_json_to_binproto_by_name(&name, &input)
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
        ;
        PossibleCaptiveNetwork,
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
        TestingChatConnectError::PossibleCaptiveNetwork => {
            ConnectError::WebSocket(libsignal_net::infra::ws::WebSocketConnectError::Transport(
                libsignal_net::infra::errors::TransportConnectError::SslFailedHandshake(
                    libsignal_net::infra::errors::FailedHandshakeReason::Cert {
                        error: boring_signal::x509::X509VerifyError::SELF_SIGNED_CERT_IN_CHAIN,
                        cert_hashes: vec![],
                    },
                ),
            ))
        }
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

mod grpc_test_cases;
use grpc_test_cases::*;

mod remote_derives {
    use libsignal_bridge_macros::{BridgedAsValue, StructuralFrom};
    use libsignal_bridge_types::net::chat::BridgeCopyBackupMediaOutcome;
    #[cfg(feature = "ffi")]
    use libsignal_bridge_types::net::chat::BridgeCopyBackupMediaOutcomeFfiResult;
    use libsignal_net_chat::grpc::devices::LinkedDevice;
    use uuid::Uuid;

    use crate::*;

    #[derive(BridgedAsValue, StructuralFrom)]
    #[structural_from(libsignal_net_chat::grpc::devices::test_cases::SetDeviceNameArgs)]
    pub(super) struct SetDeviceNameArgs {
        id: u8,
        encrypted_name: Vec<u8>,
    }
    #[derive(BridgedAsValue, StructuralFrom)]
    #[structural_from(libsignal_net_chat::grpc::devices::test_cases::SetDeviceNameOut)]
    pub(super) enum SetDeviceNameOut {
        Success,
        DeviceNotFound,
    }

    #[derive(BridgedAsValue, StructuralFrom)]
    #[structural_from(libsignal_net_chat::grpc::devices::test_cases::RemoveDeviceArgs)]
    pub(super) struct RemoveDeviceArgs {
        id: u8,
    }
    #[derive(BridgedAsValue, StructuralFrom)]
    #[structural_from(libsignal_net_chat::grpc::devices::test_cases::RemoveDeviceOut)]
    pub(super) enum RemoveDeviceOut {
        Success,
    }

    #[derive(BridgedAsValue, StructuralFrom)]
    #[structural_from(libsignal_net_chat::grpc::usernames::test_cases::ReserveUsernameHashArgs)]
    pub(super) struct ReserveUsernameHashArgs {
        usernames: BridgeVec<[u8; 32]>,
    }
    #[derive(BridgedAsValue, StructuralFrom)]
    #[structural_from(libsignal_net_chat::grpc::usernames::test_cases::ReserveUsernameHashOut)]
    pub(super) enum ReserveUsernameHashOut {
        Success([u8; 32]),
        UsernameNotAvailable,
    }

    #[derive(BridgedAsValue, StructuralFrom)]
    #[structural_from(libsignal_net_chat::grpc::usernames::test_cases::SetUsernameLinkArgs)]
    pub struct SetUsernameLinkArgs {
        pub username_ciphertext: Vec<u8>,
        pub keep_link_handle: bool,
    }
    #[derive(BridgedAsValue, StructuralFrom)]
    #[structural_from(libsignal_net_chat::grpc::usernames::test_cases::SetUsernameLinkOut)]
    pub enum SetUsernameLinkOut {
        Success(Uuid),
        UsernameNotSet,
    }
    #[derive(BridgedAsValue, StructuralFrom)]
    #[structural_from(libsignal_net_chat::grpc::devices::test_cases::GetDevicesOut)]
    pub struct GetDevicesOut {
        pub devices: BridgeVec<LinkedDevice>,
    }

    #[derive(BridgedAsValue, StructuralFrom)]
    #[structural_from(libsignal_net_chat::grpc::backups::test_cases::CopyBackupMediaOut)]
    #[bridge(arg = false)]
    pub(super) enum CopyBackupMediaOut {
        Item(BridgeCopyBackupMediaOutcome),
        InvalidDataInStream,
        CredentialRejected,
        CredentialRejectedWithoutAppropriateServerInfo,
    }
}

#[bridge_fn(nice = true)]
fn TESTING_SetDeviceNameTests()
-> GrpcTestCases<remote_derives::SetDeviceNameArgs, remote_derives::SetDeviceNameOut> {
    libsignal_net_chat::grpc::devices::test_cases::set_device_name_test_cases().into()
}

#[bridge_fn(nice = true)]
fn TESTING_RemoveDeviceTests()
-> GrpcTestCases<remote_derives::RemoveDeviceArgs, remote_derives::RemoveDeviceOut> {
    libsignal_net_chat::grpc::devices::test_cases::remove_device_test_cases().into()
}

#[bridge_fn(nice = true)]
fn TESTING_ReserveUsernameHashTests()
-> GrpcTestCases<remote_derives::ReserveUsernameHashArgs, remote_derives::ReserveUsernameHashOut> {
    libsignal_net_chat::grpc::usernames::test_cases::reserve_username_hash_test_cases().into()
}
#[bridge_fn(nice = true)]
fn TESTING_SetUsernameLinkTests()
-> GrpcTestCases<remote_derives::SetUsernameLinkArgs, remote_derives::SetUsernameLinkOut> {
    libsignal_net_chat::grpc::usernames::test_cases::set_username_link_test_cases().into()
}
#[bridge_fn(nice = true)]
fn TESTING_DeleteUsernameHashTests() -> GrpcTestCases<(), ()> {
    libsignal_net_chat::grpc::usernames::test_cases::delete_username_hash_test_cases().into()
}
#[bridge_fn(nice = true)]
fn TESTING_DeleteUsernameLinkTests() -> GrpcTestCases<(), ()> {
    libsignal_net_chat::grpc::usernames::test_cases::delete_username_link_test_cases().into()
}
#[bridge_fn(nice = true)]
fn TESTING_GetDevicesTests() -> GrpcTestCases<(), remote_derives::GetDevicesOut> {
    libsignal_net_chat::grpc::devices::test_cases::get_devices_test_cases().into()
}
// setPushToken is only bridged where each token kind is used: APNs for Swift
// and FCM for Java. (Desktop never sets a push token.)
#[bridge_fn(nice = true, jni = false, node = false)]
fn TESTING_SetPushTokenApnsTests() -> GrpcTestCases<String, ()> {
    libsignal_net_chat::grpc::devices::test_cases::set_push_token_apns_test_cases().into()
}
#[bridge_fn(nice = true, ffi = false, node = false)]
fn TESTING_SetPushTokenFcmTests() -> GrpcTestCases<String, ()> {
    libsignal_net_chat::grpc::devices::test_cases::set_push_token_fcm_test_cases().into()
}
#[bridge_fn(nice = true)]
fn TESTING_ClearPushTokenTests() -> GrpcTestCases<(), ()> {
    libsignal_net_chat::grpc::devices::test_cases::clear_push_token_test_cases().into()
}

#[bridge_fn(jni = false, node = false, nice = true)]
fn TESTING_CopyBackupMediaTests() -> GrpcTestCases<
    BridgeVec<BridgeCopyBackupMediaItem>,
    BridgeVec<remote_derives::CopyBackupMediaOut>,
> {
    GrpcTestCases::from_generalized_test_cases(
        libsignal_net_chat::grpc::backups::test_cases::copy_media_test_cases(),
    )
}

#[bridge_fn(jni = false, node = false, nice = true)]
fn TESTING_forceEmitVecOfBridgeCopyBackupMediaOut() -> BridgeVec<remote_derives::CopyBackupMediaOut>
{
    unreachable!()
}
