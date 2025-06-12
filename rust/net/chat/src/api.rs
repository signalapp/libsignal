//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

//! The `api` module and its submodules define the abstraction over anything that "behaves like
//! chat-server".

use libsignal_net::infra::errors::LogSafeDisplay;

pub mod profiles;
pub mod usernames;

/// Marker wrapper for unauthenticated connections.
#[derive(derive_more::Deref)]
pub struct Unauth<T>(pub T);

/// Authorization for requests on unauthenticated connections involving other users.
///
/// TODO: for multi-recipient message sends *specifically* there's one more kind of authorization,
/// "this is a story". That should be handled as a separate type since other requests don't have
/// that.
pub enum UserBasedAuthorization {
    AccessKey([u8; 16]),
    Group(zkgroup::groups::GroupSendFullToken),
}

#[derive(Debug, thiserror::Error, displaydoc::Display)]
#[ignore_extra_doc_attributes]
pub enum RequestError<E> {
    /// the request timed out
    Timeout,
    /// the server explicitly disconnected us because we connected elsewhere with the same credentials
    ConnectedElsewhere,
    /// the server explicitly disconnected us for some reason other than that we connected elsewhere
    ConnectionInvalidated,
    /// {0}
    RetryLater(#[from] libsignal_net::infra::errors::RetryLater),
    /// retry after completing a rate limit challenge {options:?}
    Challenge {
        token: String,
        // TODO: Move this type into libsignal-net-chat.
        options: Vec<libsignal_net::registration::RequestedInformation>,
    },
    /// transport error: {log_safe}
    Transport { log_safe: String },
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
impl<E> LogSafeDisplay for RequestError<E> where E: LogSafeDisplay {}

/// A convenience trait covering all Chat APIs.
///
/// This should be extended to include any new submodules' traits.
pub trait UnauthenticatedChatApi:
    profiles::UnauthenticatedChatApi + usernames::UnauthenticatedChatApi
{
}
impl<T> UnauthenticatedChatApi for T where
    T: profiles::UnauthenticatedChatApi + usernames::UnauthenticatedChatApi
{
}
