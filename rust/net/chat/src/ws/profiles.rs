//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::time::Duration;

use async_trait::async_trait;
use libsignal_core::Aci;
use libsignal_net::chat::{ChatConnection, Request};
use libsignal_net::infra::AsHttpHeader as _;
use serde_with::serde_as;

use super::TryIntoResponse as _;
use crate::api::profiles::ProfileKeyCredentialRequestError;
use crate::api::{RequestError, Unauth, UserBasedAuthorization};

type Base64Padded =
    serde_with::base64::Base64<serde_with::base64::Standard, serde_with::formats::Padded>;

#[async_trait]
impl crate::api::profiles::UnauthenticatedChatApi for Unauth<ChatConnection> {
    async fn get_profile_key_credential(
        &self,
        peer_aci: Aci,
        profile_key: zkgroup::profiles::ProfileKey,
        request: zkgroup::profiles::ProfileKeyCredentialRequest,
        auth: UserBasedAuthorization,
    ) -> Result<
        zkgroup::profiles::ExpiringProfileKeyCredentialResponse,
        RequestError<ProfileKeyCredentialRequestError>,
    > {
        let response = self
            .send(
                Request {
                    method: http::Method::GET,
                    path: format!(
                        "/v1/profile/{}/{}/{}?credentialType=expiringProfileKey",
                        peer_aci.service_id_string(),
                        profile_key.get_profile_key_version(peer_aci).as_ref(),
                        hex::encode(zkgroup::serialize(&request)),
                    )
                    .parse()
                    .expect("valid"),
                    headers: http::HeaderMap::from_iter([auth.as_header()]),
                    body: None,
                },
                // TODO: Figure out timeouts for libsignal-net-chat APIs.
                Duration::MAX,
            )
            .await?;

        // Over the websocket interface, this is a combination API. We only parse the single field
        // we care about.
        #[serde_as]
        #[derive(serde::Deserialize)]
        struct GetProfileResponse {
            #[serde_as(as = "Base64Padded")]
            credential: Vec<u8>,
        }

        let GetProfileResponse { credential } = response.try_into_response().map_err(|e| {
            e.into_request_error(|response| {
                Some(RequestError::Other(match response.status.as_u16() {
                    401 => ProfileKeyCredentialRequestError::AuthFailed,
                    404 => ProfileKeyCredentialRequestError::VersionNotFound,
                    _ => return None,
                }))
            })
        })?;

        zkgroup::deserialize(&credential).map_err(|e| RequestError::Unexpected {
            log_safe: e.to_string(),
        })
    }
}
