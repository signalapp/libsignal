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
use serde_with::serde_as;

use super::{CustomError, OverWs, ResponseError, TryIntoResponse, WsConnection};
use crate::api::{RequestError, Unauth};
use crate::logging::{Redact, RedactBase64};

type Base64Url =
    serde_with::base64::Base64<serde_with::base64::UrlSafe, serde_with::formats::Unpadded>;

#[async_trait]
impl<T: WsConnection> crate::api::usernames::UnauthenticatedChatApi<OverWs> for Unauth<T> {
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

    async fn look_up_username_link(
        &self,
        uuid: uuid::Uuid,
        entropy: &[u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
    ) -> Result<Option<usernames::Username>, RequestError<usernames::UsernameLinkError>> {
        let response = self
            .send(
                "unauth",
                &format!("/v1/accounts/username_link/{}", Redact(&uuid)),
                Request {
                    method: http::Method::GET,
                    path: format!("/v1/accounts/username_link/{uuid}")
                        .parse()
                        .expect("valid"),
                    headers: http::HeaderMap::new(),
                    body: None,
                },
            )
            .await?;

        #[serde_as]
        #[derive(serde::Deserialize)]
        struct UsernameLinkResponse {
            #[serde(rename = "usernameLinkEncryptedValue")]
            #[serde_as(as = "Base64Url")]
            encrypted_username: Vec<u8>,
        }

        let encrypted_username = match response.try_into_response() {
            Ok(UsernameLinkResponse { encrypted_username }) => encrypted_username,
            Err(ResponseError::UnrecognizedStatus { status, response })
                if status.as_u16() == 404 =>
            {
                if !response.body.unwrap_or_default().is_empty() {
                    log::warn!("ignoring body for 404 result from look_up_username_link");
                }
                return Ok(None);
            }
            Err(e) => return Err(e.into_request_error(CustomError::no_custom_handling)),
        };

        let plaintext_username = usernames::decrypt_username(entropy, &encrypted_username)
            .map_err(RequestError::Other)?;

        let validated_username = usernames::Username::new(&plaintext_username).map_err(|e| {
            // Exhaustively match UsernameError to make sure there's nothing we shouldn't log.
            let _username_error_carries_no_information_that_would_be_bad_to_log = match e {
                usernames::UsernameError::MissingSeparator
                | usernames::UsernameError::NicknameCannotBeEmpty
                | usernames::UsernameError::NicknameCannotStartWithDigit
                | usernames::UsernameError::BadNicknameCharacter
                | usernames::UsernameError::NicknameTooShort
                | usernames::UsernameError::NicknameTooLong
                | usernames::UsernameError::DiscriminatorCannotBeEmpty
                | usernames::UsernameError::DiscriminatorCannotBeZero
                | usernames::UsernameError::DiscriminatorCannotBeSingleDigit
                | usernames::UsernameError::DiscriminatorCannotHaveLeadingZeros
                | usernames::UsernameError::BadDiscriminatorCharacter
                | usernames::UsernameError::DiscriminatorTooLarge => {}
            };
            log::warn!("username link decrypted to an invalid username: {e}");
            log::debug!(
                "username link decrypted to '{plaintext_username}', which is not valid: {e}"
            );
            // The user didn't ever type this username, so the precise way in which it's invalid
            // isn't important. Treat this equivalent to having found garbage data in the link. This
            // simplifies error handling for callers.
            RequestError::Other(usernames::UsernameLinkError::InvalidDecryptedDataStructure)
        })?;

        Ok(Some(validated_username))
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
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
    fn test_hash_lookup(response: chat::Response) -> Result<Option<Aci>, RequestError<Infallible>> {
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

    const EXPECTED_USERNAME: &str = "moxie.01";
    const ENCRYPTED_USERNAME: &str = "kj5ah-VbEgjpfJsNt-Wto2H626DRmJSVpYPy0yPOXA8kiSFkBCD8ysFlJ-Z3MhiAnt_R3Nm7ZY0W5fiRDLVbhaE2z-KO2xdf5NcVbkewCzhvveecS3hHskDp1aSfbvwTZNNGPmAuKWvJ1MPdHzsF0w";
    const ENCRYPTED_USERNAME_ENTROPY: [u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE] =
        const_str::hex!("4302c613c092a51c5394becffeb6f697300a605348e93f03c3db95e0b03d28f1");
    const ENCRYPTED_NON_USERNAME: &str = "Fn4icLoXVbZHMEK44DovO2cLlVZpRY4mzd95TTU3OxSBBJqh3CKeHt3HMBS7B9jkmcPU-hpqzUwflBHlfZwyDQ2bg5FBl_IJN1RL7nQCeEsFQm1yYJNthNOP4JfeW7dlaiC_M9JFeysrn08S_QxniQ";
    const ENCRYPTED_NON_USERNAME_ENTROPY: [u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE] =
        const_str::hex!("ecb41bf9bdf73bd7d0b5dd2d3f17f323cdc57dbabad0ae1549a83a75d894247c");

    #[test_case(json(
        200, format!(r#"{{"usernameLinkEncryptedValue":"{ENCRYPTED_USERNAME}"}}"#)
    ) => matches Ok(Some(username)) if username == EXPECTED_USERNAME)]
    #[test_case(json(
        200, r#"{"usernameLinkEncryptedValue":"!garbage!"}"#
    ) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(empty(404) => matches Ok(None))]
    #[test_case(empty(500) => matches Err(RequestError::ServerSideError))]
    fn test_link_lookup(
        response: chat::Response,
    ) -> Result<Option<String>, RequestError<usernames::UsernameLinkError>> {
        let validator = RequestValidator {
            expected: Request {
                method: http::Method::GET,
                path: http::uri::PathAndQuery::from_static(
                    "/v1/accounts/username_link/00000000-0000-0000-0000-000000000000",
                ),
                headers: http::HeaderMap::new(),
                body: None,
            },
            response,
        };
        Unauth(validator)
            .look_up_username_link(uuid::Uuid::nil(), &ENCRYPTED_USERNAME_ENTROPY)
            .now_or_never()
            .expect("sync")
            .map(|u| u.map(|u| u.to_string()))
    }

    #[test]
    fn test_link_lookup_with_bad_entropy() {
        let validator = RequestValidator {
            expected: Request {
                method: http::Method::GET,
                path: http::uri::PathAndQuery::from_static(
                    "/v1/accounts/username_link/00000000-0000-0000-0000-000000000000",
                ),
                headers: http::HeaderMap::new(),
                body: None,
            },
            response: json(
                200,
                format!(r#"{{"usernameLinkEncryptedValue":"{ENCRYPTED_USERNAME}"}}"#),
            ),
        };
        let err = Unauth(validator)
            .look_up_username_link(
                uuid::Uuid::nil(),
                &[0; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
            )
            .now_or_never()
            .expect("sync")
            .expect_err("should have failed");
        assert_matches!(
            err,
            RequestError::Other(usernames::UsernameLinkError::HmacMismatch)
        );
    }

    #[test]
    fn test_link_lookup_with_bad_username() {
        let validator = RequestValidator {
            expected: Request {
                method: http::Method::GET,
                path: http::uri::PathAndQuery::from_static(
                    "/v1/accounts/username_link/00000000-0000-0000-0000-000000000000",
                ),
                headers: http::HeaderMap::new(),
                body: None,
            },
            response: json(
                200,
                format!(r#"{{"usernameLinkEncryptedValue":"{ENCRYPTED_NON_USERNAME}"}}"#),
            ),
        };
        let err = Unauth(validator)
            .look_up_username_link(uuid::Uuid::nil(), &ENCRYPTED_NON_USERNAME_ENTROPY)
            .now_or_never()
            .expect("sync")
            .expect_err("should have failed");
        assert_matches!(
            err,
            RequestError::Other(usernames::UsernameLinkError::InvalidDecryptedDataStructure)
        );
    }
}
