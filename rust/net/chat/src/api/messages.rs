//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use libsignal_core::{DeviceId, ServiceId};

use super::RequestError;

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

#[async_trait]
pub trait UnauthenticatedChatApi {
    async fn send_multi_recipient_message(
        &self,
        payload: bytes::Bytes,
        timestamp: libsignal_protocol::Timestamp,
        auth: MultiRecipientSendAuthorization,
        online_only: bool,
        urgent: bool,
    ) -> Result<MultiRecipientMessageResponse, RequestError<MultiRecipientSendFailure>>;
}
