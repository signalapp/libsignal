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

/// Wraps [`usernames::Username::new`] with error handling appropriate for a username retrieved from
/// a link.
pub(crate) fn validate_username_from_link(
    username: &str,
) -> Result<usernames::Username, RequestError<usernames::UsernameLinkError>> {
    usernames::Username::new(username).map_err(|e| {
        // Exhaustively match UsernameError to make sure there's nothing we shouldn't log.
        match e {
            usernames::UsernameError::MissingSeparator
            | usernames::UsernameError::NicknameCannotBeEmpty
            | usernames::UsernameError::NicknameCannotStartWithDigit
            | usernames::UsernameError::BadNicknameCharacter
            | usernames::UsernameError::NicknameTooShort
            | usernames::UsernameError::NicknameTooLong
            | usernames::UsernameError::DiscriminatorCannotBeEmpty
            | usernames::UsernameError::DiscriminatorCannotBeZero
            | usernames::UsernameError::DiscriminatorCannotBeSingleDigit
            | usernames::UsernameError::DiscriminatorCannotHaveLeadingZeros
            | usernames::UsernameError::BadDiscriminatorCharacter
            | usernames::UsernameError::DiscriminatorTooLarge => {}
        }
        log::warn!("username link decrypted to an invalid username: {e}");
        log::debug!("username link decrypted to '{username}', which is not valid: {e}");
        // The user didn't ever type this username, so the precise way in which it's invalid
        // isn't important. Treat this equivalent to having found garbage data in the link. This
        // simplifies error handling for callers.
        RequestError::Other(usernames::UsernameLinkError::InvalidDecryptedDataStructure)
    })
}
