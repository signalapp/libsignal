//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;

use async_trait::async_trait;
use displaydoc::Display;
use itertools::Itertools as _;
use libsignal_core::{DeviceId, ServiceId};
use libsignal_net::infra::errors::LogSafeDisplay;

use super::{AllowRateLimitChallenges, RequestError, UploadForm, UserBasedAuthorization};
use crate::logging::Redact;

pub struct SingleOutboundMessage<T> {
    pub device_id: DeviceId,
    pub registration_id: u32,
    pub contents: T,
}

pub type SingleOutboundSealedSenderMessage<'a> = SingleOutboundMessage<Cow<'a, [u8]>>;

pub type SingleOutboundUnsealedMessage<'a> =
    SingleOutboundMessage<Cow<'a, libsignal_protocol::CiphertextMessage>>;

impl SingleOutboundUnsealedMessage<'_> {
    /// Asserts that the messages in a list are all compatible and use a ciphertext format
    /// appropriate for unsealed sends.
    ///
    /// Examples:
    /// - "all 1:1 messages" (`PreKey` or `Whisper`)
    /// - "all plaintext messages" (decryption errors)
    /// - but not sender key messages, which can't be sent unsealed
    /// - and not a mix of the above
    pub(crate) fn assert_valid_unsealed_message_types(messages: &[Self]) {
        Self::assert_valid_unsealed_message_types_impl(
            messages.iter().map(|m| m.contents.message_type()),
        );
    }

    /// The implementation of [`Self::assert_valid_unsealed_message_types`], broken out for testing.
    fn assert_valid_unsealed_message_types_impl(
        mut types: impl Iterator<Item = libsignal_protocol::CiphertextMessageType>,
    ) {
        fn representative_message_type(
            ty: libsignal_protocol::CiphertextMessageType,
        ) -> libsignal_protocol::CiphertextMessageType {
            match ty {
                libsignal_protocol::CiphertextMessageType::PreKey
                | libsignal_protocol::CiphertextMessageType::Whisper => {
                    libsignal_protocol::CiphertextMessageType::Whisper
                }

                libsignal_protocol::CiphertextMessageType::Plaintext => ty,

                libsignal_protocol::CiphertextMessageType::SenderKey => {
                    panic!("cannot send SenderKey message unsealed")
                }
            }
        }

        let first_message_type = types.next().expect("cannot send messages to 0 devices");
        let message_type_to_check_against = representative_message_type(first_message_type);
        for next_message_type in types {
            // Not using assert_eq! because we want to show the original message types in the error, not
            // the representative ones.
            assert!(
                message_type_to_check_against == representative_message_type(next_message_type),
                "cannot mix arbitrary outgoing message types ({first_message_type:?} and {next_message_type:?})"
            );
        }
    }
}

#[derive(Debug)]
pub struct MultiRecipientMessageResponse {
    pub unregistered_ids: Vec<ServiceId>,
}

#[derive(Debug, displaydoc::Display, derive_more::From)]
pub enum SealedSendFailure {
    /// Invalid authorization for send
    Unauthorized,
    /// The target account was not found
    ServiceIdNotFound,
    /// Mismatched devices for recipient
    MismatchedDevices(#[from] MismatchedDeviceError),
}
impl LogSafeDisplay for SealedSendFailure {}

#[derive(Debug)]
pub enum MultiRecipientSendFailure {
    Unauthorized,
    MismatchedDevices(Vec<MismatchedDeviceError>),
}

#[derive(Debug, displaydoc::Display, derive_more::From)]
pub enum UnsealedSendFailure {
    /// The target account was not found
    ServiceIdNotFound,
    /// Mismatched devices for recipient
    MismatchedDevices(#[from] MismatchedDeviceError),
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct MismatchedDeviceError {
    pub account: ServiceId,
    pub missing_devices: Vec<DeviceId>,
    pub extra_devices: Vec<DeviceId>,
    pub stale_devices: Vec<DeviceId>,
}

#[derive(derive_more::From)]
pub enum UserBasedSendAuthorization {
    Story,
    User(#[from] UserBasedAuthorization),
}

pub enum MultiRecipientSendAuthorization {
    Story,
    Group(zkgroup::groups::GroupSendFullToken),
}

/// High-level chat-server APIs for messaging
///
/// ### Generic?
///
/// The type parameter `T` is a marker to distinguish blanket impls that would otherwise overlap.
/// Any concrete type will only impl this trait in one way; anywhere that needs to use
/// UnauthenticatedChatApi generically should accept an arbitrary `T` here.
#[async_trait]
pub trait UnauthenticatedChatApi<T> {
    const ALLOW_RATE_LIMIT_CHALLENGES: AllowRateLimitChallenges = AllowRateLimitChallenges::No;

    /// Send a sealed 1:1 message.
    ///
    /// `contents` should include one message for each device of `destination`. It must not be
    /// empty.
    async fn send_message(
        &self,
        destination: ServiceId,
        timestamp: libsignal_protocol::Timestamp,
        contents: &[SingleOutboundSealedSenderMessage<'_>],
        auth: UserBasedSendAuthorization,
        online_only: bool,
        urgent: bool,
    ) -> Result<(), RequestError<SealedSendFailure>>;

    async fn send_multi_recipient_message(
        &self,
        payload: bytes::Bytes,
        timestamp: libsignal_protocol::Timestamp,
        auth: MultiRecipientSendAuthorization,
        online_only: bool,
        urgent: bool,
    ) -> Result<MultiRecipientMessageResponse, RequestError<MultiRecipientSendFailure>>;
}

/// The request size was larger than the maximum supported upload size
#[derive(Debug, Display)]
pub struct UploadTooLarge;

/// High-level chat-server APIs for messaging
///
/// ### Generic?
///
/// The type parameter `T` is a marker to distinguish blanket impls that would otherwise overlap.
/// Any concrete type will only impl this trait in one way; anywhere that needs to use
/// AuthenticatedChatApi generically should accept an arbitrary `T` here.
#[async_trait]
pub trait AuthenticatedChatApi<T> {
    const ALLOW_RATE_LIMIT_CHALLENGES: AllowRateLimitChallenges = AllowRateLimitChallenges::Yes;

    /// Send an unsealed 1:1 message.
    ///
    /// `contents` should include one message for each device of `destination`. It must not be
    /// empty.
    async fn send_message(
        &self,
        destination: ServiceId,
        timestamp: libsignal_protocol::Timestamp,
        contents: &[SingleOutboundUnsealedMessage<'_>],
        online_only: bool,
        urgent: bool,
    ) -> Result<(), RequestError<UnsealedSendFailure>>;

    /// Send an unsealed message to the current user's other devices.
    ///
    /// `contents` should include one message for each other device. It must not be empty.
    async fn send_sync_message(
        &self,
        timestamp: libsignal_protocol::Timestamp,
        contents: &[SingleOutboundUnsealedMessage<'_>],
        urgent: bool,
    ) -> Result<(), RequestError<MismatchedDeviceError>>;

    async fn get_upload_form(
        &self,
        upload_size: u64,
    ) -> Result<UploadForm, RequestError<UploadTooLarge>>;
}

impl std::fmt::Display for MultiRecipientSendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MultiRecipientSendFailure::Unauthorized => {
                f.write_str("Invalid authorization for send")
            }
            MultiRecipientSendFailure::MismatchedDevices(mismatched_device_errors) => {
                write!(
                    f,
                    "mismatched devices for {}",
                    mismatched_device_errors
                        .iter()
                        .map(|entry| Redact(&entry.account))
                        .join(", ")
                )
            }
        }
    }
}
impl LogSafeDisplay for MultiRecipientSendFailure {}

#[cfg(test)]
mod test {
    use libsignal_protocol::CiphertextMessageType;
    use test_case::test_case;

    use super::*;

    #[test_case(&[] => panics)]
    #[test_case(&[CiphertextMessageType::Whisper])]
    #[test_case(&[CiphertextMessageType::PreKey])]
    #[test_case(&[CiphertextMessageType::Plaintext])]
    #[test_case(&[CiphertextMessageType::SenderKey] => panics)]
    #[test_case(&[CiphertextMessageType::Whisper, CiphertextMessageType::Whisper, CiphertextMessageType::PreKey, CiphertextMessageType::Whisper])]
    #[test_case(&[CiphertextMessageType::PreKey, CiphertextMessageType::Whisper, CiphertextMessageType::Whisper])]
    #[test_case(&[CiphertextMessageType::Plaintext, CiphertextMessageType::Plaintext, CiphertextMessageType::Plaintext])]
    #[test_case(&[CiphertextMessageType::Plaintext, CiphertextMessageType::Whisper] => panics)]
    #[test_case(&[CiphertextMessageType::PreKey, CiphertextMessageType::Plaintext] => panics)]
    fn test_valid_unsealed_sender_message_types(types: &[CiphertextMessageType]) {
        SingleOutboundUnsealedMessage::assert_valid_unsealed_message_types_impl(
            types.iter().copied(),
        )
    }
}
