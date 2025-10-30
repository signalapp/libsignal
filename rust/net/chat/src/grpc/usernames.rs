//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use async_trait::async_trait;
use libsignal_core::Aci;
use libsignal_net_grpc::proto::chat::account::accounts_anonymous_client::AccountsAnonymousClient;
use libsignal_net_grpc::proto::chat::account::*;

use super::{GrpcServiceProvider, OverGrpc, into_default_request_error, log_and_send};
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
        let result = log_and_send("unauth", &log_safe_description, || {
            account_service.lookup_username_hash(request)
        })
        .await;

        let id = match result.map(tonic::Response::into_inner) {
            Ok(LookupUsernameHashResponse { service_identifier }) => service_identifier,
            Err(e) if e.code() == tonic::Code::NotFound => return Ok(None),
            Err(e) => return Err(into_default_request_error(e)),
        }
        .ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing service ID in response".to_owned(),
        })?
        .try_into_service_id()
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
        _uuid: uuid::Uuid,
        _entropy: &[u8; usernames::constants::USERNAME_LINK_ENTROPY_SIZE],
    ) -> Result<Option<usernames::Username>, RequestError<usernames::UsernameLinkError>> {
        unimplemented!();
    }
}

impl std::fmt::Display for Redact<&'_ LookupUsernameHashRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(LookupUsernameHashRequest { username_hash }) = self;
        f.debug_struct("LookupUsernameHash")
            .field("username_hash", &RedactHex(&hex::encode(username_hash)))
            .finish()
    }
}

#[cfg(test)]
mod test {
    use futures_util::FutureExt as _;
    use libsignal_net_grpc::proto::chat::common::{IdentityType, ServiceIdentifier};
    use test_case::test_case;
    use uuid::{Uuid, uuid};

    use super::*;
    use crate::api::usernames::UnauthenticatedChatApi;
    use crate::grpc::testutil::{RequestValidator, err, ok, req};

    const ACI_UUID: Uuid = uuid!("9d0652a3-dcc3-4d11-975f-74d61598733f");

    #[test_case(ok(LookupUsernameHashResponse {
        service_identifier: Some(ServiceIdentifier {
            identity_type: IdentityType::Aci.into(),
            uuid: ACI_UUID.as_bytes().to_vec(),
        }),
    }) => matches Ok(Some(aci)) if Uuid::from(aci) == ACI_UUID)]
    #[test_case(ok(LookupUsernameHashResponse {
        service_identifier: Some(ServiceIdentifier {
            identity_type: IdentityType::Pni.into(),
            uuid: ACI_UUID.as_bytes().to_vec(),
        }),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(LookupUsernameHashResponse {
        service_identifier: Some(ServiceIdentifier {
            identity_type: 50,
            uuid: ACI_UUID.as_bytes().to_vec(),
        }),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(LookupUsernameHashResponse {
        service_identifier: Some(ServiceIdentifier {
            identity_type: IdentityType::Aci.into(),
            uuid: vec![1, 2, 3],
        }),
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(ok(LookupUsernameHashResponse {
        service_identifier: None,
    }) => matches Err(RequestError::Unexpected { .. }))]
    #[test_case(err(tonic::Code::NotFound) => matches Ok(None))]
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
}
