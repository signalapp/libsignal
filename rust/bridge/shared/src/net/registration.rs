//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use std::collections::HashSet;

use libsignal_bridge_macros::{bridge_fn, bridge_io};
use libsignal_bridge_types::net::registration::{
    ConnectChatBridge, RegisterAccountInner, RegisterAccountRequest, RegistrationAccountAttributes,
    RegistrationCreateSessionRequest, RegistrationPushTokenType, RegistrationService,
};
use libsignal_bridge_types::net::TokioAsyncContext;
use libsignal_bridge_types::*;
use libsignal_net::registration::{
    CreateSessionError, ForServiceIds, RegisterAccountError, RegisterAccountResponse,
    RegisterResponseBadge, RegistrationSession, RequestError, RequestVerificationCodeError,
    RequestedInformation, ResumeSessionError, SessionId, SignedPreKeyBody, SubmitVerificationError,
    UpdateSessionError, VerificationTransport,
};
use libsignal_protocol::*;
use uuid::Uuid;

use crate::support::*;

bridge_handle_fns!(RegistrationService, clone = false, ffi = false);
bridge_handle_fns!(RegistrationSession, clone = false, ffi = false);
bridge_handle_fns!(
    RegisterAccountRequest,
    clone = false,
    ffi = false,
    jni = false
);
bridge_handle_fns!(RegisterAccountResponse, clone = false, ffi = false);
bridge_handle_fns!(
    RegistrationAccountAttributes,
    clone = false,
    ffi = false,
    jni = false
);

#[bridge_io(TokioAsyncContext, ffi = false)]
async fn RegistrationService_CreateSession(
    create_session: RegistrationCreateSessionRequest,
    connect_chat: Box<dyn ConnectChatBridge>,
) -> Result<RegistrationService, RequestError<CreateSessionError>> {
    RegistrationService::create_session(
        connect_chat,
        tokio::runtime::Handle::current(),
        create_session,
    )
    .await
}

#[bridge_io(TokioAsyncContext, ffi = false)]
async fn RegistrationService_ResumeSession(
    session_id: AsType<SessionId, String>,
    number: String,
    connect_chat: Box<dyn ConnectChatBridge>,
) -> Result<RegistrationService, RequestError<ResumeSessionError>> {
    RegistrationService::resume_session(
        connect_chat,
        tokio::runtime::Handle::current(),
        session_id.into_inner(),
        number,
    )
    .await
}

#[bridge_io(TokioAsyncContext, ffi = false)]
async fn RegistrationService_RequestPushChallenge(
    service: &RegistrationService,
    push_token: String,
    push_token_type: RegistrationPushTokenType,
) -> Result<(), RequestError<UpdateSessionError>> {
    service
        .0
        .lock()
        .await
        .request_push_challenge(&push_token, push_token_type)
        .await
}

#[bridge_io(TokioAsyncContext, ffi = false)]
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

#[bridge_io(TokioAsyncContext, ffi = false)]
async fn RegistrationService_RequestVerificationCode(
    service: &RegistrationService,
    transport: AsType<VerificationTransport, String>,
    client: String,
    languages: Box<[String]>,
) -> Result<(), RequestError<RequestVerificationCodeError>> {
    service
        .0
        .lock()
        .await
        .request_verification_code(transport.into_inner(), &client, &languages)
        .await
}

#[bridge_io(TokioAsyncContext, ffi = false)]
async fn RegistrationService_SubmitVerificationCode(
    service: &RegistrationService,
    code: String,
) -> Result<(), RequestError<SubmitVerificationError>> {
    service.0.lock().await.submit_verification_code(&code).await
}

#[bridge_io(TokioAsyncContext, ffi = false)]
async fn RegistrationService_SubmitCaptcha(
    service: &RegistrationService,
    captcha_value: String,
) -> Result<(), RequestError<UpdateSessionError>> {
    service.0.lock().await.submit_captcha(&captcha_value).await
}

#[bridge_io(TokioAsyncContext, ffi = false, jni = false)]
async fn RegistrationService_RegisterAccount(
    service: &RegistrationService,
    register_account: &RegisterAccountRequest,
    account_attributes: &RegistrationAccountAttributes,
) -> Result<RegisterAccountResponse, RequestError<RegisterAccountError>> {
    use libsignal_net::registration::AccountKeys;

    let RegisterAccountInner {
        message_notification,
        device_transfer,
        account_password,
        identity_keys,
        signed_pre_keys,
        pq_last_resort_pre_keys,
    } = register_account
        .0
        .lock()
        .expect("not poisoned")
        .take()
        .expect("not taken");

    service
        .0
        .lock()
        .await
        .register_account(
            message_notification.as_deref(),
            account_attributes.into(),
            device_transfer,
            ForServiceIds {
                aci: AccountKeys {
                    identity_key: identity_keys.aci.as_ref().expect("key was provided"),
                    signed_pre_key: signed_pre_keys
                        .aci
                        .as_ref()
                        .expect("key was provided")
                        .as_deref(),
                    pq_last_resort_pre_key: pq_last_resort_pre_keys
                        .aci
                        .as_ref()
                        .expect("key was provided")
                        .as_deref(),
                },
                pni: AccountKeys {
                    identity_key: identity_keys.pni.as_ref().expect("key was provided"),
                    signed_pre_key: signed_pre_keys
                        .pni
                        .as_ref()
                        .expect("key was provided")
                        .as_deref(),
                    pq_last_resort_pre_key: pq_last_resort_pre_keys
                        .pni
                        .as_ref()
                        .expect("key was provided")
                        .as_deref(),
                },
            },
            &account_password,
        )
        .await
}

#[bridge_fn(ffi = false)]
fn RegistrationService_SessionId(service: &RegistrationService) -> String {
    service
        .0
        .blocking_lock()
        .session_id()
        .as_url_path_segment()
        .to_owned()
}

#[bridge_fn(ffi = false)]
fn RegistrationService_RegistrationSession(service: &RegistrationService) -> RegistrationSession {
    service.0.blocking_lock().session_state().clone()
}

#[bridge_fn(ffi = false)]
fn RegistrationSession_GetAllowedToRequestCode(session: &RegistrationSession) -> bool {
    session.allowed_to_request_code
}

#[bridge_fn(ffi = false)]
fn RegistrationSession_GetVerified(session: &RegistrationSession) -> bool {
    session.verified
}

#[bridge_fn(ffi = false)]
fn RegistrationSession_GetNextCallSeconds(session: &RegistrationSession) -> Option<u32> {
    session
        .next_call
        .map(|d| d.as_secs().try_into().unwrap_or(u32::MAX))
}

#[bridge_fn(ffi = false)]
fn RegistrationSession_GetNextSmsSeconds(session: &RegistrationSession) -> Option<u32> {
    session
        .next_sms
        .map(|d| d.as_secs().try_into().unwrap_or(u32::MAX))
}

#[bridge_fn(ffi = false)]
fn RegistrationSession_GetNextVerificationAttemptSeconds(
    session: &RegistrationSession,
) -> Option<u32> {
    session
        .next_verification_attempt
        .map(|d| d.as_secs().try_into().unwrap_or(u32::MAX))
}

type RegistrationSessionRequestedInformation = RequestedInformation;

#[bridge_fn(ffi = false)]
fn RegistrationSession_GetRequestedInformation(
    session: &RegistrationSession,
) -> Box<[RegistrationSessionRequestedInformation]> {
    session.requested_information.iter().copied().collect()
}

#[bridge_fn(ffi = false, jni = false)]
fn RegisterAccountRequest_Create() -> RegisterAccountRequest {
    RegisterAccountRequest(Some(RegisterAccountInner::default()).into())
}

#[bridge_fn(ffi = false, jni = false)]
fn RegisterAccountRequest_SetSkipDeviceTransfer(register_account: &RegisterAccountRequest) {
    register_account
        .0
        .lock()
        .expect("not poisoned")
        .as_mut()
        .expect("not taken")
        .device_transfer = Some(libsignal_net::registration::SkipDeviceTransfer);
}

#[bridge_fn(ffi = false, jni = false)]
fn RegisterAccountRequest_SetAccountPassword(
    register_account: &RegisterAccountRequest,
    account_password: &[u8],
) {
    register_account
        .0
        .lock()
        .expect("not poisoned")
        .as_mut()
        .expect("not taken")
        .account_password = account_password.into()
}

#[bridge_fn(ffi = false, jni = false)]
fn RegisterAccountRequest_SetIdentityPublicKey(
    register_account: &RegisterAccountRequest,
    identity_type: AsType<ServiceIdKind, u8>,
    identity_key: &PublicKey,
) {
    let mut guard = register_account.0.lock().expect("not poisoned");
    let account = guard.as_mut().expect("not taken");
    *account.identity_keys.get_mut(identity_type.into_inner()) = Some(*identity_key);
}

/// cbindgen: ignore
type SignedPublicPreKey = SignedPreKeyBody<Box<[u8]>>;

#[bridge_fn(ffi = false, jni = false)]
fn RegisterAccountRequest_SetIdentitySignedPreKey(
    register_account: &RegisterAccountRequest,
    identity_type: AsType<ServiceIdKind, u8>,
    signed_pre_key: SignedPublicPreKey,
) {
    let mut guard = register_account.0.lock().expect("not poisoned");
    let account = guard.as_mut().expect("not taken");
    *account.signed_pre_keys.get_mut(identity_type.into_inner()) = Some(signed_pre_key);
}

#[bridge_fn(ffi = false, jni = false)]
fn RegisterAccountRequest_SetIdentityPqLastResortPreKey(
    register_account: &RegisterAccountRequest,
    identity_type: AsType<ServiceIdKind, u8>,
    pq_last_resort_pre_key: SignedPublicPreKey,
) {
    let mut guard = register_account.0.lock().expect("not poisoned");
    let account = guard.as_mut().expect("not taken");
    *account
        .pq_last_resort_pre_keys
        .get_mut(identity_type.into_inner()) = Some(pq_last_resort_pre_key);
}

#[bridge_fn(ffi = false, jni = false)]
fn RegistrationAccountAttributes_Create(
    recovery_password: Box<[u8]>,
    aci_registration_id: u16,
    pni_registration_id: u16,
    registration_lock: Option<String>,
    unidentified_access_key: Option<&[u8; 16]>,
    unrestricted_unidentified_access: bool,
    capabilities: Box<[String]>,
    discoverable_by_phone_number: bool,
) -> RegistrationAccountAttributes {
    RegistrationAccountAttributes {
        recovery_password,
        aci_registration_id,
        pni_registration_id,
        registration_lock,
        unidentified_access_key: unidentified_access_key.copied(),
        unrestricted_unidentified_access,
        capabilities: HashSet::from_iter(capabilities),
        discoverable_by_phone_number,
    }
}

#[bridge_fn(ffi = false)]
fn RegisterAccountResponse_GetIdentity(
    response: &RegisterAccountResponse,
    identity_type: AsType<ServiceIdKind, u8>,
) -> ServiceId {
    match identity_type.into_inner() {
        ServiceIdKind::Aci => response.aci.into(),
        ServiceIdKind::Pni => response.pni.into(),
    }
}

#[bridge_fn(ffi = false)]
fn RegisterAccountResponse_GetNumber(response: &RegisterAccountResponse) -> &str {
    &response.number
}

#[bridge_fn(ffi = false)]
fn RegisterAccountResponse_GetUsernameHash(response: &RegisterAccountResponse) -> Option<&[u8]> {
    response.username_hash.as_deref()
}

#[bridge_fn(ffi = false)]
fn RegisterAccountResponse_GetUsernameLinkHandle(
    response: &RegisterAccountResponse,
) -> Option<Uuid> {
    response.username_link_handle
}

#[bridge_fn(ffi = false)]
fn RegisterAccountResponse_GetStorageCapable(response: &RegisterAccountResponse) -> bool {
    response.storage_capable
}

#[bridge_fn(ffi = false)]
fn RegisterAccountResponse_GetReregistration(response: &RegisterAccountResponse) -> bool {
    response.reregistration
}

#[bridge_fn(ffi = false)]
fn RegisterAccountResponse_GetEntitlementBadges(
    response: &RegisterAccountResponse,
) -> Box<[RegisterResponseBadge]> {
    response.entitlements.badges.clone()
}

#[bridge_fn(ffi = false)]
fn RegisterAccountResponse_GetEntitlementBackupLevel(
    response: &RegisterAccountResponse,
) -> Option<u64> {
    response
        .entitlements
        .backup
        .as_ref()
        .map(|backup| backup.backup_level)
}

#[bridge_fn(ffi = false)]
fn RegisterAccountResponse_GetEntitlementBackupExpirationSeconds(
    response: &RegisterAccountResponse,
) -> Option<u64> {
    response
        .entitlements
        .backup
        .as_ref()
        .map(|backup| backup.expiration.as_secs())
}
