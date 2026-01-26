//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use libsignal_bridge_macros::bridge_io;
use libsignal_bridge_types::net::TokioAsyncContext;
use libsignal_bridge_types::net::chat::UnauthenticatedChatConnection;
use libsignal_bridge_types::*;
use libsignal_core::ServiceId;
use libsignal_net_chat::api::RequestError;
use libsignal_net_chat::api::profiles::UnauthenticatedAccountExistenceApi;

use crate::support::*;

#[bridge_io(TokioAsyncContext)]
async fn UnauthenticatedChatConnection_account_exists(
    chat: &UnauthenticatedChatConnection,
    account: ServiceId,
) -> Result<bool, RequestError<Infallible>> {
    chat.as_typed(|chat| chat.account_exists(account)).await
}
