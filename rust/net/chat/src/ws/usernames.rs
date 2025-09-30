//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use async_trait::async_trait;
use base64::Engine;
use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use libsignal_core::Aci;
use libsignal_net::chat::Request;

use super::{CustomError, ResponseError, TryIntoResponse, WsConnection};
use crate::api::{RequestError, Unauth};
use crate::logging::RedactBase64;

#[async_trait]
impl<T: WsConnection> crate::api::usernames::UnauthenticatedChatApi for Unauth<T> {
    async fn look_up_username_hash(
        &self,
        hash: &[u8],
    ) -> Result<Option<Aci>, RequestError<Infallible>> {
        let encoded_hash = BASE64_URL_SAFE_NO_PAD.encode(hash);
        let response = self
            .send(
                "unauth",
                &format!("/v1/accounts/username_hash/{}", RedactBase64(&encoded_hash)),
                Request {
                    method: http::Method::GET,
                    path: format!("/v1/accounts/username_hash/{encoded_hash}")
                        .parse()
                        .expect("valid"),
                    headers: http::HeaderMap::new(),
                    body: None,
                },
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
            Err(e) => return Err(e.into_request_error(CustomError::no_custom_handling)),
        };

        let aci = Aci::parse_from_service_id_string(&uuid_string).ok_or_else(|| {
            RequestError::Unexpected {
                log_safe: "could not parse UUID".to_owned(),
            }
        })?;

        Ok(Some(aci))
    }
}

#[cfg(test)]
mod test {
    use futures_util::FutureExt as _;
    use libsignal_net::chat;
    use test_case::test_case;

    use super::*;
    use crate::api::usernames::UnauthenticatedChatApi;
    use crate::ws::testutil::{RequestValidator, empty, json};

    const ACI_UUID: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";

    #[test_case(json(
        200, format!(r#"{{"uuid":"{ACI_UUID}"}}"#)
    ) => matches Ok(Some(aci)) if aci.service_id_string() == ACI_UUID)]
    #[test_case(json(
        200, r#"{"uuid":"garbage"}"#
    ) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(empty(404) => matches Ok(None))]
    #[test_case(empty(500) => matches Err(RequestError::ServerSideError))]
    fn test(response: chat::Response) -> Result<Option<Aci>, RequestError<Infallible>> {
        let validator = RequestValidator {
            expected: Request {
                method: http::Method::GET,
                path: http::uri::PathAndQuery::from_static("/v1/accounts/username_hash/AP___w"),
                headers: http::HeaderMap::new(),
                body: None,
            },
            response,
        };
        // Not realistic, but includes bits that encode differently in base64 vs base64url.
        let hash = &[0x00, 0xff, 0xff, 0xff];
        Unauth(validator)
            .look_up_username_hash(hash)
            .now_or_never()
            .expect("sync")
    }
}
