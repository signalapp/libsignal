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
