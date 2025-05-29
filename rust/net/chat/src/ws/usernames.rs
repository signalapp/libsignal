//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;
use std::time::Duration;

use async_trait::async_trait;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::Engine;
use libsignal_core::Aci;
use libsignal_net::chat::{ChatConnection, Request};

use super::{ResponseError, TryIntoResponse};
use crate::api::{RequestError, Unauth};

#[async_trait]
impl crate::api::usernames::UnauthenticatedChatApi for Unauth<ChatConnection> {
    async fn look_up_username_hash(
        &self,
        hash: &[u8],
    ) -> Result<Option<Aci>, RequestError<Infallible>> {
        let response = self
            .send(
                Request {
                    method: http::Method::GET,
                    path: format!(
                        "/v1/accounts/username_hash/{}",
                        BASE64_URL_SAFE_NO_PAD.encode(hash),
                    )
                    .parse()
                    .expect("valid"),
                    headers: http::HeaderMap::new(),
                    body: None,
                },
                // TODO: Figure out timeouts for libsignal-net-chat APIs.
                Duration::MAX,
            )
            .await?;

        #[derive(serde::Deserialize)]
        struct UsernameHashResponse {
            uuid: String,
        }

        let uuid_string = match response.try_into_response() {
            Ok(UsernameHashResponse { uuid }) => uuid,
            Err(ResponseError::UnrecognizedStatus { status, response })
                if status.as_u16() == 404 =>
            {
                if !response.body.unwrap_or_default().is_empty() {
                    log::warn!("ignoring body for 404 result from look_up_username_hash");
                }
                return Ok(None);
            }
            Err(e) => return Err(e.into_request_error(|_response| None)),
        };

        let aci = Aci::parse_from_service_id_string(&uuid_string).ok_or_else(|| {
            RequestError::Unexpected {
                log_safe: "could not parse UUID".to_owned(),
            }
        })?;

        Ok(Some(aci))
    }
}
