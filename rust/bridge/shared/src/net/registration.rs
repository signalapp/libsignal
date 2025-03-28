//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_bridge_types::net::registration::{ConnectChatBridge, RegistrationService};
use libsignal_bridge_types::net::TokioAsyncContext;
use libsignal_bridge_types::*;
use libsignal_net::registration::{
    CreateSession, CreateSessionError, PushTokenType, RegistrationSession, RequestError,
    RequestVerificationCodeError, RequestedInformation, ResumeSessionError, SessionId,
    SubmitVerificationError, UpdateSessionError, VerificationTransport,
};

use crate::support::*;

bridge_handle_fns!(RegistrationService, clone = false, ffi = false, jni = false);
bridge_handle_fns!(RegistrationSession, clone = false, ffi = false, jni = false);

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn RegistrationService_CreateSession(
    create_session: CreateSession,
    connect_chat: Box<dyn ConnectChatBridge>,
) -> Result<RegistrationService, RequestError<CreateSessionError>> {
    RegistrationService::create_session(
        connect_chat,
        tokio::runtime::Handle::current(),
        create_session,
    )
    .await
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn RegistrationService_ResumeSession(
    session_id: AsType<SessionId, String>,
    connect_chat: Box<dyn ConnectChatBridge>,
) -> Result<RegistrationService, RequestError<ResumeSessionError>> {
    RegistrationService::resume_session(
        connect_chat,
        tokio::runtime::Handle::current(),
        session_id.into_inner(),
    )
    .await
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn RegistrationService_RequestPushChallenge(
    service: &RegistrationService,
    push_token: String,
    push_token_type: PushTokenType,
) -> Result<(), RequestError<UpdateSessionError>> {
    service
        .0
        .lock()
        .await
        .request_push_challenge(&push_token, push_token_type)
        .await
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn RegistrationService_SubmitPushChallenge(
    service: &RegistrationService,
    push_challenge: String,
) -> Result<(), RequestError<UpdateSessionError>> {
    service
        .0
        .lock()
        .await
        .submit_push_challenge(&push_challenge)
        .await
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn RegistrationService_RequestVerificationCode(
    service: &RegistrationService,
    transport: AsType<VerificationTransport, String>,
    client: String,
) -> Result<(), RequestError<RequestVerificationCodeError>> {
    service
        .0
        .lock()
        .await
        .request_verification_code(transport.into_inner(), &client)
        .await
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn RegistrationService_SubmitVerificationCode(
    service: &RegistrationService,
    code: String,
) -> Result<(), RequestError<SubmitVerificationError>> {
    service.0.lock().await.submit_verification_code(&code).await
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn RegistrationService_SubmitCaptcha(
    service: &RegistrationService,
    captcha_value: String,
) -> Result<(), RequestError<UpdateSessionError>> {
    service.0.lock().await.submit_captcha(&captcha_value).await
}

#[bridge_fn(ffi = false, jni = false)]
fn RegistrationService_SessionId(service: &RegistrationService) -> String {
    service.0.blocking_lock().session_id().to_string()
}

#[bridge_fn(ffi = false, jni = false)]
fn RegistrationService_RegistrationSession(service: &RegistrationService) -> RegistrationSession {
    service.0.blocking_lock().session_state().clone()
}

#[bridge_fn(ffi = false, jni = false)]
fn RegistrationSession_GetAllowedToRequestCode(session: &RegistrationSession) -> bool {
    session.allowed_to_request_code
}

#[bridge_fn(ffi = false, jni = false)]
fn RegistrationSession_GetVerified(session: &RegistrationSession) -> bool {
    session.verified
}

#[bridge_fn(ffi = false, jni = false)]
fn RegistrationSession_GetNextCallSeconds(session: &RegistrationSession) -> Option<u32> {
    session
        .next_call
        .map(|d| d.as_secs().try_into().unwrap_or(u32::MAX))
}

#[bridge_fn(ffi = false, jni = false)]
fn RegistrationSession_GetNextSmsSeconds(session: &RegistrationSession) -> Option<u32> {
    session
        .next_sms
        .map(|d| d.as_secs().try_into().unwrap_or(u32::MAX))
}

#[bridge_fn(ffi = false, jni = false)]
fn RegistrationSession_GetNextVerificationAttemptSeconds(
    session: &RegistrationSession,
) -> Option<u32> {
    session
        .next_verification_attempt
        .map(|d| d.as_secs().try_into().unwrap_or(u32::MAX))
}

#[bridge_fn(ffi = false, jni = false)]
fn RegistrationSession_GetRequestedInformation(
    session: &RegistrationSession,
) -> Vec<RequestedInformation> {
    session.requested_information.iter().copied().collect()
}
