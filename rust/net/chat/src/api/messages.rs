//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::borrow::Cow;
use std::convert::Infallible;

use async_trait::async_trait;
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

#[derive(Debug)]
pub struct MultiRecipientMessageResponse {
    pub unregistered_ids: Vec<ServiceId>,
}

#[derive(Debug, displaydoc::Display)]
pub enum SealedSendFailure {
    /// Invalid authorization for send
    Unauthorized,
    /// The target account was not found
    ServiceIdNotFound,
    /// Mismatched devices for recipient
    MismatchedDevices(MismatchedDeviceError),
}
impl LogSafeDisplay for SealedSendFailure {}

#[derive(Debug)]
pub enum MultiRecipientSendFailure {
    Unauthorized,
    MismatchedDevices(Vec<MismatchedDeviceError>),
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct MismatchedDeviceError {
    pub account: ServiceId,
    pub missing_devices: Vec<DeviceId>,
    pub extra_devices: Vec<DeviceId>,
    pub stale_devices: Vec<DeviceId>,
}

pub enum UserBasedSendAuthorization {
    Story,
    User(UserBasedAuthorization),
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

    async fn send_message<'a>(
        &self,
        destination: ServiceId,
        timestamp: libsignal_protocol::Timestamp,
        contents: Vec<SingleOutboundSealedSenderMessage<'a>>,
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

    async fn get_upload_form(&self) -> Result<UploadForm, RequestError<Infallible>>;
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
