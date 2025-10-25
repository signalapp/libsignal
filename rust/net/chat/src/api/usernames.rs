//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use async_trait::async_trait;
use libsignal_core::Aci;

use super::RequestError;

#[async_trait]
pub trait UnauthenticatedChatApi {
    async fn look_up_username_hash(
        &self,
        hash: &[u8],
    ) -> Result<Option<Aci>, RequestError<Infallible>>;

    async fn look_up_username_link(
        &self,
        uuid: uuid::Uuid,
        entropy: &[u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
    ) -> Result<Option<usernames::Username>, RequestError<usernames::UsernameLinkError>>;
}
