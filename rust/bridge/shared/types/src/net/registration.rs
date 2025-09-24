//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashSet;
use std::future::Future;
use std::panic::{RefUnwindSafe, UnwindSafe};

use futures_util::TryFutureExt as _;
use libsignal_net_chat::api::registration::{
    CreateSession, CreateSessionError, ForServiceIds, NewMessageNotification,
    ProvidedAccountAttributes, PushToken, RegisterAccountResponse, RegistrationSession,
    ResumeSessionError, SessionId, SignedPreKeyBody, SkipDeviceTransfer, UnidentifiedAccessKey,
};
use libsignal_net_chat::registration::{self as net_registration, ConnectUnauthChat, RequestError};
use libsignal_protocol::PublicKey;

use crate::*;

pub struct RegistrationService(
    pub tokio::sync::Mutex<net_registration::RegistrationService<'static>>,
);

// The implementation of this type does contain interior mutability, but the
// interior type is itself UnwindSafe so there's no danger of observing a
// logically inconsistent state.
impl RefUnwindSafe for RegistrationService where
    net_registration::RegistrationService<'static>: UnwindSafe
{
}

/// Subset of arguments needed to call
/// [`net_registration::RegistrationService::register_account`].
#[derive(Default)]
pub struct RegisterAccountInner {
    pub message_notification: NewMessageNotification<String>,
    pub device_transfer: Option<SkipDeviceTransfer>,
    pub account_password: Box<str>,
    pub identity_keys: ForServiceIds<Option<PublicKey>>,
    pub signed_pre_keys: ForServiceIds<Option<SignedPreKeyBody<Box<[u8]>>>>,
    pub pq_last_resort_pre_keys: ForServiceIds<Option<SignedPreKeyBody<Box<[u8]>>>>,
}

pub struct RegisterAccountRequest(pub std::sync::Mutex<Option<RegisterAccountInner>>);

#[derive(Clone)]
pub struct AccountAttributes {
    pub recovery_password: Box<[u8]>,
    pub aci_registration_id: u16,
    pub pni_registration_id: u16,
    pub registration_lock: Option<String>,
    pub unidentified_access_key: UnidentifiedAccessKey,
    pub unrestricted_unidentified_access: bool,
    pub capabilities: HashSet<String>,
    pub discoverable_by_phone_number: bool,
}

// Aliases so that places that refer to syntactic argument names (e.g.
// jni::jni_arg and friends) aren't ambiguous.
pub type RegistrationCreateSessionRequest = CreateSession;
pub type RegistrationPushToken = PushToken;
pub type RegistrationAccountAttributes = AccountAttributes;

// Alias the type exposed across the bridge since the macros don't support
// templates well.
pub type SignedPublicPreKey = SignedPreKeyBody<Box<[u8]>>;

bridge_as_handle!(RegistrationService);
bridge_as_handle!(RegistrationSession);
bridge_as_handle!(RegisterAccountRequest);
bridge_as_handle!(RegisterAccountResponse);
bridge_as_handle!(RegistrationAccountAttributes);

/// Precursor to a [`Box<dyn ConnectUnauthChat>`](ConnectUnauthChat).
///
/// Functionally a `FnOnce(Handle) -> Box<dyn ConnectUnauthChat>` but named for clarity.
pub trait ConnectChatBridge: Send + UnwindSafe {
    /// Converts `self` into a `ConnectUnauthChat` impl.
    ///
    /// The provided runtime handle can be used to spawn tasks needed by the
    /// implementation.
    fn create_chat_connector(
        self: Box<Self>,
        runtime: tokio::runtime::Handle,
    ) -> Box<dyn ConnectUnauthChat + Send + Sync + UnwindSafe>;
}

impl RegistrationService {
    pub fn create_session(
        connect_bridge: Box<dyn ConnectChatBridge>,
        tokio_runtime: tokio::runtime::Handle,
        create_session: CreateSession,
    ) -> impl Future<Output = Result<Self, RequestError<CreateSessionError>>> + Send {
        net_registration::RegistrationService::create_session(
            create_session,
            connect_bridge.create_chat_connector(tokio_runtime),
        )
        .map_ok(|registration| Self(registration.into()))
    }

    pub fn resume_session(
        connect_bridge: Box<dyn ConnectChatBridge>,
        tokio_runtime: tokio::runtime::Handle,
        session_id: SessionId,
        number: String,
    ) -> impl Future<Output = Result<Self, RequestError<ResumeSessionError>>> + Send {
        net_registration::RegistrationService::resume_session(
            session_id,
            number,
            connect_bridge.create_chat_connector(tokio_runtime),
        )
        .map_ok(|registration| Self(registration.into()))
    }
}

impl<'a> From<&'a AccountAttributes> for ProvidedAccountAttributes<'a> {
    fn from(value: &'a AccountAttributes) -> Self {
        let AccountAttributes {
            recovery_password,
            aci_registration_id,
            pni_registration_id,
            registration_lock,
            unidentified_access_key,
            unrestricted_unidentified_access,
            capabilities,
            discoverable_by_phone_number,
        } = value;
        Self {
            recovery_password,
            registration_id: *aci_registration_id,
            pni_registration_id: *pni_registration_id,
            name: None,
            registration_lock: registration_lock.as_deref(),
            unidentified_access_key,
            unrestricted_unidentified_access: *unrestricted_unidentified_access,
            capabilities: capabilities.iter().map(String::as_str).collect(),
            discoverable_by_phone_number: *discoverable_by_phone_number,
        }
    }
}
