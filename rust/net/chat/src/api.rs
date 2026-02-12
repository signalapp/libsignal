//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! The `api` module and its submodules define the abstraction over anything that "behaves like
//! chat-server".

use std::convert::Infallible;

use libsignal_net::infra::errors::LogSafeDisplay;
use ref_cast::RefCast as _;

pub mod backups;
pub mod keys;
pub mod keytrans;
pub mod messages;
pub mod profiles;
pub mod registration;
pub mod usernames;

/// Marker wrapper for unauthenticated connections.
///
/// You can get `&Unauth<Connection>` from `&Connection` using `Into`.
#[derive(derive_more::Deref, ref_cast::RefCast)]
#[repr(transparent)]
pub struct Unauth<T>(pub T);

impl<'a, T> From<&'a T> for &'a Unauth<T> {
    fn from(value: &'a T) -> Self {
        Unauth::ref_cast(value)
    }
}

/// Marker wrapper for registration connections.
#[derive(derive_more::Deref)]
pub struct Registration<T>(pub T);

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
pub enum AllowRateLimitChallenges {
    No,
    Yes,
}

/// Authorization for requests on unauthenticated connections involving other users.
///
/// For multi-recipient messages, see [messages::MultiRecipientSendAuthorization].
pub enum UserBasedAuthorization {
    AccessKey([u8; 16]),
    Group(zkgroup::groups::GroupSendFullToken),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(Clone))]
#[ignore_extra_doc_attributes]
pub enum RequestError<E, D = DisconnectedError> {
    /// the request timed out
    Timeout,
    /// {0}
    Disconnected(D),
    /// {0}
    RetryLater(#[from] libsignal_net::infra::errors::RetryLater),
    /// {0}
    Challenge(#[from] RateLimitChallenge),
    /// server-side error, retryable with backoff
    ServerSideError,
    /// {log_safe}
    ///
    /// This is distinct from `Transport` in that the request completed and we got a response, but
    /// nevertheless there was an unexpected failure. This likely indicates a bug (or at least a
    /// missing case) on either the client or server side.
    Unexpected { log_safe: String },
    /// {0}
    Other(E),
}
impl<E, D> LogSafeDisplay for RequestError<E, D>
where
    E: LogSafeDisplay,
    D: LogSafeDisplay,
{
}

impl<E, D> From<Infallible> for RequestError<E, D> {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}

impl<E, D> RequestError<E, D> {
    /// Substitutes one `Other` error type for another.
    ///
    /// This is a *flat* map because the transformation is allowed to return a different
    /// `RequestError` case (usually `Unexpected`).
    pub fn flat_map_other<E2>(
        self,
        f: impl FnOnce(E) -> RequestError<E2, D>,
    ) -> RequestError<E2, D> {
        match self {
            RequestError::Timeout => RequestError::Timeout,
            RequestError::Disconnected(d) => RequestError::Disconnected(d),
            RequestError::RetryLater(retry_later) => RequestError::RetryLater(retry_later),
            RequestError::Challenge(challenge) => RequestError::Challenge(challenge),
            RequestError::ServerSideError => RequestError::ServerSideError,
            RequestError::Unexpected { log_safe } => RequestError::Unexpected { log_safe },
            RequestError::Other(e) => f(e),
        }
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(Clone))]
#[ignore_extra_doc_attributes]
pub enum DisconnectedError {
    /// the server explicitly disconnected us because we connected elsewhere with the same credentials
    ConnectedElsewhere,
    /// the server explicitly disconnected us for some reason other than that we connected elsewhere
    ConnectionInvalidated,
    /// transport error: {log_safe}
    Transport { log_safe: String },
    /// the connection was closed
    Closed,
}

impl LogSafeDisplay for DisconnectedError {}

impl<E> From<DisconnectedError> for RequestError<E> {
    fn from(value: DisconnectedError) -> Self {
        Self::Disconnected(value)
    }
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[cfg_attr(test, derive(Clone))]
/// retry after completing a rate limit challenge {options:?}
pub struct RateLimitChallenge {
    pub token: String,
    pub options: Vec<ChallengeOption>,
}
impl LogSafeDisplay for RateLimitChallenge {}

#[derive(
    Copy, Clone, Debug, PartialEq, Eq, Hash, strum::Display, strum::EnumString, strum::EnumIter,
)]
#[repr(u8)]
#[strum(serialize_all = "camelCase")]
pub enum ChallengeOption {
    PushChallenge,
    Captcha,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct UploadForm {
    pub cdn: u32,
    pub key: String,
    pub headers: Vec<(String, String)>,
    pub signed_upload_url: String,
}

/// A convenience trait covering all Chat APIs.
///
/// This should be extended to include any new submodules' traits.
///
/// ### Generic?
///
/// The type parameter `T` is a marker to distinguish blanket impls that would otherwise overlap.
/// Any concrete type will only impl this trait in one way; anywhere that needs to use
/// UnauthenticatedChatApi generically should accept an arbitrary `T` here.
pub trait UnauthenticatedChatApi<T>:
    backups::UnauthenticatedChatApi<T>
    + keys::UnauthenticatedChatApi<T>
    + keytrans::UnauthenticatedChatApi
    + messages::UnauthenticatedChatApi<T>
    + profiles::UnauthenticatedChatApi
    + usernames::UnauthenticatedChatApi<T>
{
}
impl<T, U> UnauthenticatedChatApi<T> for U where
    U: backups::UnauthenticatedChatApi<T>
        + keys::UnauthenticatedChatApi<T>
        + keytrans::UnauthenticatedChatApi
        + messages::UnauthenticatedChatApi<T>
        + profiles::UnauthenticatedChatApi
        + usernames::UnauthenticatedChatApi<T>
{
}

#[cfg(test)]
pub(crate) mod testutil {
    use rand::SeedableRng as _;

    /// A standard RNG used for exact-match tests that (normally) depend on randomness.
    pub(crate) fn fixed_seed_test_rng() -> impl rand::CryptoRng + Send {
        rand_chacha::ChaCha20Rng::seed_from_u64(0)
    }
}
