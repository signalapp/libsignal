//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use itertools::Itertools as _;
use libsignal_core::{DeviceId, ServiceId};
use libsignal_net::infra::errors::LogSafeDisplay;

use super::{AllowRateLimitChallenges, RequestError};
use crate::logging::Redact;

#[derive(Debug)]
pub struct MultiRecipientMessageResponse {
    pub unregistered_ids: Vec<ServiceId>,
}

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

    async fn send_multi_recipient_message(
        &self,
        payload: bytes::Bytes,
        timestamp: libsignal_protocol::Timestamp,
        auth: MultiRecipientSendAuthorization,
        online_only: bool,
        urgent: bool,
    ) -> Result<MultiRecipientMessageResponse, RequestError<MultiRecipientSendFailure>>;
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
