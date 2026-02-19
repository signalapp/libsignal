//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use libsignal_core::{DeviceId, ServiceId};
use libsignal_protocol::{IdentityKey, PreKeyBundle};

use super::{RequestError, UserBasedAuthorization};

/// Specifier to limit scope of pre-keys request to a specific device or all devices on the account.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DeviceSpecifier {
    /// Request pre-keys for all devices on the account.
    AllDevices,
    /// Request pre-keys for a specific device.
    Specific(DeviceId),
}

/// Recoverable errors produced by [`UnauthenticatedChatApi::get_pre_keys`].
#[derive(Debug)]
pub enum GetPreKeysFailure {
    /// The provided authorization is invalid for this fetch.
    Unauthorized,
    /// No keys were found for the target account or device.
    NotFound,
}

#[async_trait]
pub trait UnauthenticatedChatApi<T> {
    /// Fetch the identity key and pre-key bundles for `target`.
    async fn get_pre_keys(
        &self,
        auth: UserBasedAuthorization,
        target: ServiceId,
        device: DeviceSpecifier,
    ) -> Result<(IdentityKey, Vec<PreKeyBundle>), RequestError<GetPreKeysFailure>>;
}
