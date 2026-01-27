//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use async_trait::async_trait;
use libsignal_core::ServiceId;
use libsignal_net_grpc::proto::chat::account::accounts_anonymous_client::AccountsAnonymousClient;
use libsignal_net_grpc::proto::chat::account::{
    CheckAccountExistenceRequest, CheckAccountExistenceResponse,
};

use crate::api::{RequestError, Unauth};
use crate::grpc::{GrpcServiceProvider, OverGrpc, log_and_send};
use crate::logging::Redact;

impl std::fmt::Display for Redact<&'_ CheckAccountExistenceRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(CheckAccountExistenceRequest { service_identifier }) = self;
        f.debug_struct("CheckAccountExistenceRequest")
            .field(
                "service_identifier",
                &service_identifier.as_ref().and_then(|service_identifier| {
                    service_identifier.try_as_service_id().map(Redact)
                }),
            )
            .finish()
    }
}

#[async_trait]
impl<T: GrpcServiceProvider> crate::api::profiles::UnauthenticatedAccountExistenceApi<OverGrpc>
    for Unauth<T>
{
    async fn account_exists(&self, account: ServiceId) -> Result<bool, RequestError<Infallible>> {
        let mut account_service = AccountsAnonymousClient::new(self.0.service());
        let request = CheckAccountExistenceRequest {
            service_identifier: Some(account.into()),
        };
        let log_safe_description = Redact(&request).to_string();
        let CheckAccountExistenceResponse { account_exists } =
            log_and_send("unauth", &log_safe_description, || {
                account_service.check_account_existence(request)
            })
            .await?
            .into_inner();
        Ok(account_exists)
    }
}

#[cfg(test)]
mod test_account_exists {
    use futures_util::FutureExt;
    use libsignal_core::{Aci, Pni};
    use test_case::test_case;
    use uuid::{Uuid, uuid};

    use super::*;
    use crate::api::profiles::UnauthenticatedAccountExistenceApi;
    use crate::grpc::testutil::{self, RequestValidator, req};

    const ACI_UUID: Uuid = uuid!("9d0652a3-dcc3-4d11-975f-74d61598733f");
    const PNI_UUID: Uuid = uuid!("796abedb-ca4e-4f18-8803-1fde5b921f9f");

    #[test_case(Aci::from(ACI_UUID).into(), true)]
    #[test_case(Pni::from(PNI_UUID).into(), true)]
    #[test_case(Aci::from(ACI_UUID).into(), false)]
    #[test_case(Pni::from(PNI_UUID).into(), false)]
    #[tokio::test]
    async fn test_it(service_id: ServiceId, found: bool) {
        let validator = RequestValidator {
            expected: req(
                "/org.signal.chat.account.AccountsAnonymous/CheckAccountExistence",
                CheckAccountExistenceRequest {
                    service_identifier: Some(service_id.into()),
                },
            ),
            response: testutil::ok(CheckAccountExistenceResponse {
                account_exists: found,
            }),
        };
        let result = Unauth(&validator)
            .account_exists(service_id)
            .now_or_never()
            .expect("sync")
            .expect("success");
        assert_eq!(result, found);
    }

    #[tokio::test]
    async fn test_invalid() {
        let validator = RequestValidator {
            expected: req(
                "/org.signal.chat.account.AccountsAnonymous/CheckAccountExistence",
                CheckAccountExistenceRequest {
                    service_identifier: Some(Aci::from(ACI_UUID).into()),
                },
            ),
            response: testutil::err(tonic::Code::DeadlineExceeded),
        };
        let result = Unauth(&validator)
            .account_exists(Aci::from(ACI_UUID).into())
            .now_or_never()
            .expect("sync")
            .expect_err("should fail");
        assert!(matches!(result, RequestError::Timeout));
    }
}
