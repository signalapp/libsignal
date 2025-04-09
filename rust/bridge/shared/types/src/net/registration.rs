//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::panic::{RefUnwindSafe, UnwindSafe};

use futures_util::TryFutureExt as _;
use libsignal_net::registration::{
    self as net_registration, ConnectChat, CreateSession, CreateSessionError, PushTokenType,
    RegistrationSession, RequestError, ResumeSessionError, SessionId,
};

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

bridge_as_handle!(RegistrationService, ffi = false);
bridge_as_handle!(RegistrationSession, ffi = false);

// Aliases so that places that refer to syntactic argument names (e.g.
// jni::jni_arg and friends) aren't ambiguous.
pub type RegistrationCreateSessionRequest = CreateSession;
pub type RegistrationPushTokenType = PushTokenType;

/// Precursor to a [`Box<dyn ConnectChat>`](ConnectChat).
///
/// Functionally a `FnOnce(Handle) -> Box<dyn ConnectChat>` but named for clarity.
pub trait ConnectChatBridge: Send {
    /// Converts `self` into a `ConnectChat` impl.
    ///
    /// The provided runtime handle can be used to spawn tasks needed by the
    /// implementation.
    fn create_chat_connector(
        self: Box<Self>,
        runtime: tokio::runtime::Handle,
    ) -> Box<dyn ConnectChat + Send + Sync + UnwindSafe>;
}

impl RegistrationService {
    pub fn create_session(
        connect_bridge: Box<dyn ConnectChatBridge>,
        tokio_runtime: tokio::runtime::Handle,
        create_session: net_registration::CreateSession,
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
