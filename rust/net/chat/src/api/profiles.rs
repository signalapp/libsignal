//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use async_trait::async_trait;
use libsignal_core::{Aci, ServiceId};

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

// TODO: once we implement a grpc backend for UnauthenticatedChatApi, merge this trait into that.
#[async_trait]
pub trait UnauthenticatedAccountExistenceApi<T> {
    async fn account_exists(&self, account: ServiceId) -> Result<bool, RequestError<Infallible>>;
}
