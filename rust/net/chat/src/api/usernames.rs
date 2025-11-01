//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use async_trait::async_trait;
use either::Either;
use libsignal_core::Aci;

use super::RequestError;

/// High-level chat-server APIs for usernames
///
/// ### Generic?
///
/// The type parameter `T` is a marker to distinguish blanket impls that would otherwise overlap.
/// Any concrete type will only impl this trait in one way; anywhere that needs to use
/// UnauthenticatedChatApi generically should accept an arbitrary `T` here.
#[async_trait]
pub trait UnauthenticatedChatApi<T> {
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

#[async_trait]
impl<A, AMarker, B, BMarker> UnauthenticatedChatApi<Either<AMarker, BMarker>> for Either<A, B>
where
    A: UnauthenticatedChatApi<AMarker> + Sync,
    B: UnauthenticatedChatApi<BMarker> + Sync,
{
    async fn look_up_username_hash(
        &self,
        hash: &[u8],
    ) -> Result<Option<Aci>, RequestError<Infallible>> {
        match self {
            Either::Left(a) => a.look_up_username_hash(hash).await,
            Either::Right(b) => b.look_up_username_hash(hash).await,
        }
    }

    async fn look_up_username_link(
        &self,
        uuid: uuid::Uuid,
        entropy: &[u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
    ) -> Result<Option<usernames::Username>, RequestError<usernames::UsernameLinkError>> {
        match self {
            Either::Left(a) => a.look_up_username_link(uuid, entropy).await,
            Either::Right(b) => b.look_up_username_link(uuid, entropy).await,
        }
    }
}
