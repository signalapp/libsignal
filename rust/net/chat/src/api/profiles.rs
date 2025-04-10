//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use libsignal_core::Aci;

use super::{RequestError, UserBasedAuthorization};

#[derive(Debug, displaydoc::Display)]
pub enum ProfileKeyCredentialRequestError {
    /// authorization failed
    AuthFailed,
    /// profile version not found
    VersionNotFound,
}

#[async_trait]
pub trait UnauthenticatedChatApi {
    async fn get_profile_key_credential(
        &self,
        peer_aci: Aci,
        profile_key: zkgroup::profiles::ProfileKey,
        request: zkgroup::profiles::ProfileKeyCredentialRequest,
        auth: UserBasedAuthorization,
    ) -> Result<
        zkgroup::profiles::ExpiringProfileKeyCredentialResponse,
        RequestError<ProfileKeyCredentialRequestError>,
    >;
}
