use std::time::Duration;

use futures_util::future::BoxFuture;
//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//
use libsignal_net::chat;
use libsignal_net::keytrans::{SearchResult, UnauthenticatedChat};

use crate::net::chat::BridgeChatConnection as _;
use crate::*;

bridge_as_handle!(SearchResult, ffi = false, node = false);

impl UnauthenticatedChat for crate::net::chat::UnauthenticatedChatConnection {
    fn send_unauthenticated(
        &self,
        request: chat::Request,
        timeout: Duration,
    ) -> BoxFuture<'_, Result<chat::Response, chat::ChatServiceError>> {
        Box::pin(self.send(request, timeout))
    }
}
