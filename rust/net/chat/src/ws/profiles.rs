//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use async_trait::async_trait;
use libsignal_core::Aci;
use libsignal_net::chat::Request;
use libsignal_net::infra::AsHttpHeader as _;
use serde_with::serde_as;

use super::{CustomError, TryIntoResponse as _, WsConnection};
use crate::api::profiles::ProfileKeyCredentialRequestError;
use crate::api::{RequestError, Unauth, UserBasedAuthorization};
use crate::logging::{Redact, RedactHex};

type Base64Padded =
    serde_with::base64::Base64<serde_with::base64::Standard, serde_with::formats::Padded>;

#[async_trait]
impl<T: WsConnection> crate::api::profiles::UnauthenticatedChatApi for Unauth<T> {
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
        let profile_key_version = profile_key.get_profile_key_version(peer_aci);
        let serialized_request = hex::encode(zkgroup::serialize(&request));
        let response = self
            .send(
                "unauth",
                &format!(
                    "/v1/profile/{}/{}/{}",
                    Redact(&peer_aci),
                    RedactHex(profile_key_version.as_ref()),
                    RedactHex(&serialized_request),
                ),
                Request {
                    method: http::Method::GET,
                    path: format!(
                        "/v1/profile/{}/{}/{}?credentialType=expiringProfileKey",
                        peer_aci.service_id_string(),
                        profile_key_version.as_ref(),
                        serialized_request,
                    )
                    .parse()
                    .expect("valid"),
                    headers: http::HeaderMap::from_iter([auth.as_header()]),
                    body: None,
                },
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
                CustomError::Err(match response.status.as_u16() {
                    401 => ProfileKeyCredentialRequestError::AuthFailed,
                    404 => ProfileKeyCredentialRequestError::VersionNotFound,
                    _ => return CustomError::NoCustomHandling,
                })
            })
        })?;

        zkgroup::deserialize(&credential).map_err(|e| RequestError::Unexpected {
            log_safe: e.to_string(),
        })
    }
}

#[cfg(test)]
mod test {
    use base64::Engine as _;
    use base64::prelude::BASE64_STANDARD;
    use futures_util::FutureExt as _;
    use libsignal_net::chat;
    use test_case::test_case;

    use super::*;
    use crate::api::profiles::UnauthenticatedChatApi;
    use crate::ws::ACCESS_KEY_HEADER_NAME;
    use crate::ws::testutil::{ProduceResponse, RequestValidator, empty, json};

    const ACI_UUID: &str = "9d0652a3-dcc3-4d11-975f-74d61598733f";

    #[tokio::test]
    async fn test_successful_request() {
        let randomness = zkgroup::TEST_ARRAY_32;
        let server_params = zkgroup::ServerSecretParams::generate(randomness);
        let aci = Aci::parse_from_service_id_string(ACI_UUID).expect("valid");
        let profile_key = zkgroup::profiles::ProfileKey::create(zkgroup::TEST_ARRAY_32_1);

        let request = server_params
            .get_public_params()
            .create_profile_key_credential_request_context(randomness, aci, profile_key);

        let credential = server_params
            .issue_expiring_profile_key_credential(
                randomness,
                &request.get_request(),
                aci,
                profile_key.get_commitment(aci),
                zkgroup::Timestamp::from_epoch_seconds(zkgroup::SECONDS_PER_DAY),
            )
            .expect("valid");

        let expected_request_path = concat!(
            "/v1/profile/9d0652a3-dcc3-4d11-975f-74d61598733f",
            "/f74078448aa501a163593a4c0b2ec4644b27a2a747639bb1a5e2af71ff355d9c",
            "/0014ee4cf2cbdad90c58980cba3f5d9b900e57b52597834580aaaf83a87f5439",
            "1faa03f125f289279492292e958f96e9f79d8f9924f866acb168a85cdb5bbc69",
            "3a12115f946407fe6154813854293c955103f82e47788ac8e227123de9d99b22",
            "6c500a11ec4a532623bc1a2a25f8664ac3e1af3b71fb59f0b6fb9ea9a647650a",
            "0f4e34696d86a7602ad0e918aabfaee4c15528d44a76842f9bf760c23f9fa5a2",
            "50a000000000000000b3e5952105bee26968d4781d7530d4a0c3fde51605eb73",
            "540ca08d30ee34080d15280d1ed736c2673ebd9ad71fc0917dfdde1a0ca259ff",
            "573e3a1a3868d2110c61f74b1fa3a5b281d85a68bd7b7c092f21bd5a45c8eef5",
            "2cb987c895737598093ca2f47bdb2251df556a2cea9186be716a394e13d4a71a",
            "4d88b8914212ecb40f238ee645547012ae531392c311138171d9ac26a56fcce8",
            "cfb617e061f3e4f50d",
            "?credentialType=expiringProfileKey"
        );

        let validator = RequestValidator {
            expected: Request {
                method: http::Method::GET,
                path: http::uri::PathAndQuery::from_static(expected_request_path),
                headers: http::HeaderMap::from_iter([(
                    ACCESS_KEY_HEADER_NAME,
                    http::HeaderValue::from_static("AAAAAAAAAAAAAAAAAAAAAA=="),
                )]),
                body: None,
            },
            response: json(
                200,
                format!(
                    r#"{{"credential":"{}"}}"#,
                    BASE64_STANDARD.encode(zkgroup::serialize(&credential))
                ),
            ),
        };

        let response = Unauth(validator)
            .get_profile_key_credential(
                aci,
                profile_key,
                request.get_request(),
                UserBasedAuthorization::AccessKey([0; zkgroup::ACCESS_KEY_LEN]),
            )
            .now_or_never()
            .expect("sync")
            .expect("success");

        server_params
            .get_public_params()
            .receive_expiring_profile_key_credential(
                &request,
                &response,
                zkgroup::Timestamp::from_epoch_seconds(0),
            )
            .expect("valid");
    }

    #[test_case(empty(401) => matches RequestError::Other(ProfileKeyCredentialRequestError::AuthFailed))]
    #[test_case(empty(404) => matches RequestError::Other(ProfileKeyCredentialRequestError::VersionNotFound))]
    #[test_case(json(200, r#"{"credential": "AA=="}"#) => matches RequestError::Unexpected { .. })]
    #[test_case(empty(500) => matches RequestError::ServerSideError)]
    #[tokio::test]
    async fn test_unsuccessful_requests(
        response: chat::Response,
    ) -> RequestError<ProfileKeyCredentialRequestError> {
        let randomness = zkgroup::TEST_ARRAY_32;
        let server_params = zkgroup::ServerSecretParams::generate(randomness);
        let aci = Aci::parse_from_service_id_string(ACI_UUID).expect("valid");
        let profile_key = zkgroup::profiles::ProfileKey::create(zkgroup::TEST_ARRAY_32_1);

        let request = server_params
            .get_public_params()
            .create_profile_key_credential_request_context(randomness, aci, profile_key);

        Unauth(ProduceResponse(response))
            .get_profile_key_credential(
                aci,
                profile_key,
                request.get_request(),
                UserBasedAuthorization::AccessKey([0; zkgroup::ACCESS_KEY_LEN]),
            )
            .now_or_never()
            .expect("sync")
            .map(|_| ())
            .expect_err("should have failed")
    }
}
