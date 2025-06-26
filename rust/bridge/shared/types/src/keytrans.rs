//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::future::Future;
use std::time::Duration;

use libsignal_net::chat;

use crate::net::chat::BridgeChatConnection;

// TODO: Remove this once UnauthenticatedChatConnection can vend an
// `Unauth<libsignal_net::chat::ChatConnection>` (which will then handle the logging part too).
impl libsignal_net_chat::ws::WsConnection for crate::net::chat::UnauthenticatedChatConnection {
    fn send(
        &self,
        _log_tag: &'static str,
        _log_safe_path: &str,
        request: chat::Request,
    ) -> impl Future<Output = Result<chat::Response, chat::SendError>> + Send {
        BridgeChatConnection::send(self, request, Duration::MAX)
    }
}

/// A wrapper around libsignal-net-chat's error scheme to stay compatible with existing KT APIs as
/// exposed at the app layer.
#[derive(Debug, derive_more::From, derive_more::Into, derive_more::Deref, thiserror::Error)]
#[error("{0}")]
pub struct BridgeError(
    libsignal_net_chat::api::RequestError<libsignal_net_chat::api::keytrans::Error>,
);

impl From<libsignal_net_chat::api::keytrans::Error> for BridgeError {
    fn from(inner: libsignal_net_chat::api::keytrans::Error) -> Self {
        Self(libsignal_net_chat::api::RequestError::Other(inner))
    }
}
