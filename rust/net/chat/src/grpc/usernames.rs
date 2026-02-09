//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use async_trait::async_trait;
use libsignal_core::Aci;
use libsignal_net_grpc::proto::chat::account::accounts_anonymous_client::AccountsAnonymousClient;
use libsignal_net_grpc::proto::chat::account::*;
use libsignal_net_grpc::proto::chat::errors;

use super::{GrpcServiceProvider, OverGrpc, log_and_send};
use crate::api::usernames::validate_username_from_link;
use crate::api::{RequestError, Unauth};
use crate::logging::{Redact, RedactHex};

#[async_trait]
impl<T: GrpcServiceProvider> crate::api::usernames::UnauthenticatedChatApi<OverGrpc> for Unauth<T> {
    async fn look_up_username_hash(
        &self,
        hash: &[u8],
    ) -> Result<Option<Aci>, RequestError<Infallible>> {
        let mut account_service = AccountsAnonymousClient::new(self.0.service());
        let request = LookupUsernameHashRequest {
            username_hash: hash.into(),
        };
        let log_safe_description = Redact(&request).to_string();
        let LookupUsernameHashResponse { response } =
            log_and_send("unauth", &log_safe_description, || {
                account_service.lookup_username_hash(request)
            })
            .await?
            .into_inner();

        let response = response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })?;

        let id = match response {
            lookup_username_hash_response::Response::ServiceIdentifier(service_id) => service_id,
            lookup_username_hash_response::Response::NotFound(errors::NotFound {}) => {
                return Ok(None);
            }
        }
        .try_as_service_id()
        .ok_or_else(|| RequestError::Unexpected {
            log_safe: "unable to parse service ID in response".to_owned(),
        })?;

        let aci = Aci::try_from(id).map_err(|_| RequestError::Unexpected {
            log_safe: format!("lookup returned {} instead of ACI", id.kind()),
        })?;

        Ok(Some(aci))
    }

    async fn look_up_username_link(
        &self,
        uuid: uuid::Uuid,
        entropy: &[u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
    ) -> Result<Option<usernames::Username>, RequestError<usernames::UsernameLinkError>> {
        let mut account_service = AccountsAnonymousClient::new(self.0.service());
        let request = LookupUsernameLinkRequest {
            username_link_handle: uuid.as_bytes().to_vec(),
        };
        let log_safe_description = Redact(&request).to_string();
        let LookupUsernameLinkResponse { response } =
            log_and_send("unauth", &log_safe_description, || {
                account_service.lookup_username_link(request)
            })
            .await?
            .into_inner();

        let response = response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })?;

        let encrypted_username = match response {
            lookup_username_link_response::Response::UsernameCiphertext(ciphertext) => ciphertext,
            lookup_username_link_response::Response::NotFound(errors::NotFound {}) => {
                return Ok(None);
            }
        };

        let plaintext_username = usernames::decrypt_username(entropy, &encrypted_username)
            .map_err(RequestError::Other)?;

        let validated_username = validate_username_from_link(&plaintext_username)?;

        Ok(Some(validated_username))
    }
}

impl std::fmt::Display for Redact<LookupUsernameHashRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(LookupUsernameHashRequest { username_hash }) = self;
        f.debug_struct("LookupUsernameHash")
            .field("username_hash", &RedactHex(&hex::encode(username_hash)))
            .finish()
    }
}

impl std::fmt::Display for Redact<LookupUsernameLinkRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(LookupUsernameLinkRequest {
            username_link_handle,
        }) = self;
        f.debug_struct("LookupUsernameLink")
            .field(
                "username_link_handle",
                &uuid::Uuid::from_slice(username_link_handle)
                    .ok()
                    .map(Redact),
            )
            .finish()
    }
}

#[cfg(test)]
mod test {
    use data_encoding_macro::base64url_nopad;
    use futures_util::FutureExt as _;
    use libsignal_net_grpc::proto::chat::common::{IdentityType, ServiceIdentifier};
    use test_case::test_case;
    use uuid::{Uuid, uuid};

    use super::*;
    use crate::api::usernames::UnauthenticatedChatApi;
    use crate::grpc::testutil::{RequestValidator, err, ok, req};

    const ACI_UUID: Uuid = uuid!("9d0652a3-dcc3-4d11-975f-74d61598733f");

    #[test_case(ok(LookupUsernameHashResponse {
        response: Some(lookup_username_hash_response::Response::ServiceIdentifier(ServiceIdentifier {
            identity_type: IdentityType::Aci.into(),
            uuid: ACI_UUID.as_bytes().to_vec(),
        })),
    }) => matches Ok(Some(aci)) if Uuid::from(aci) == ACI_UUID)]
    #[test_case(ok(LookupUsernameHashResponse {
        response: Some(lookup_username_hash_response::Response::ServiceIdentifier(ServiceIdentifier {
            identity_type: IdentityType::Pni.into(),
            uuid: ACI_UUID.as_bytes().to_vec(),
        })),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(LookupUsernameHashResponse {
        response: Some(lookup_username_hash_response::Response::ServiceIdentifier(ServiceIdentifier {
            identity_type: 50,
            uuid: ACI_UUID.as_bytes().to_vec(),
        })),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(LookupUsernameHashResponse {
        response: Some(lookup_username_hash_response::Response::ServiceIdentifier(ServiceIdentifier {
            identity_type: IdentityType::Aci.into(),
            uuid: vec![1, 2, 3],
        })),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(LookupUsernameHashResponse {
        response: None,
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(LookupUsernameHashResponse {
        response: Some(lookup_username_hash_response::Response::NotFound(Default::default())),
    }) => matches Ok(None))]
    #[test_case(err(tonic::Code::Internal) => matches Err(RequestError::Unexpected { .. }))]
    fn test_hash_lookup(
        response: http::Response<Vec<u8>>,
    ) -> Result<Option<Aci>, RequestError<Infallible>> {
        // Not realistic, but not likely to show up by accident.
        let hash = &[0x00, 0xff, 0xff, 0xff];

        let validator = RequestValidator {
            expected: req(
                "/org.signal.chat.account.AccountsAnonymous/LookupUsernameHash",
                LookupUsernameHashRequest {
                    username_hash: hash.to_vec(),
                },
            ),
            response,
        };

        Unauth(&validator)
            .look_up_username_hash(hash)
            .now_or_never()
            .expect("sync")
    }

    const EXPECTED_USERNAME: &str = "moxie.01";
    const ENCRYPTED_USERNAME: &[u8] = &base64url_nopad!(
        "kj5ah-VbEgjpfJsNt-Wto2H626DRmJSVpYPy0yPOXA8kiSFkBCD8ysFlJ-Z3MhiAnt_R3Nm7ZY0W5fiRDLVbhaE2z-KO2xdf5NcVbkewCzhvveecS3hHskDp1aSfbvwTZNNGPmAuKWvJ1MPdHzsF0w"
    );
    const ENCRYPTED_USERNAME_ENTROPY: [u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE] =
        const_str::hex!("4302c613c092a51c5394becffeb6f697300a605348e93f03c3db95e0b03d28f1");

    #[test_case(ok(LookupUsernameLinkResponse {
        response: Some(lookup_username_link_response::Response::UsernameCiphertext(ENCRYPTED_USERNAME.to_vec()))
    }) => matches Ok(Some(username)) if username == EXPECTED_USERNAME)]
    #[test_case(ok(LookupUsernameLinkResponse {
        response: Some(lookup_username_link_response::Response::UsernameCiphertext(b"!garbage!".to_vec()))
    }) => matches Err(RequestError::Other(usernames::UsernameLinkError::UsernameLinkDataTooShort)))]
    #[test_case(ok(LookupUsernameLinkResponse {
        response: Some(lookup_username_link_response::Response::NotFound(Default::default()))
    }) => matches Ok(None))]
    #[test_case(err(tonic::Code::Internal) => matches Err(RequestError::Unexpected { .. }))]
    fn test_link_lookup(
        response: http::Response<Vec<u8>>,
    ) -> Result<Option<String>, RequestError<usernames::UsernameLinkError>> {
        let validator = RequestValidator {
            expected: req(
                "/org.signal.chat.account.AccountsAnonymous/LookupUsernameLink",
                LookupUsernameLinkRequest {
                    username_link_handle: uuid::Uuid::nil().as_bytes().to_vec(),
                },
            ),
            response,
        };

        Unauth(&validator)
            .look_up_username_link(uuid::Uuid::nil(), &ENCRYPTED_USERNAME_ENTROPY)
            .now_or_never()
            .expect("sync")
            .map(|u| u.map(|u| u.to_string()))
    }
}
