//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use libsignal_net_grpc::proto::chat::keys::keys_client::KeysClient;
use libsignal_net_grpc::proto::chat::keys::{GetPreKeyCountRequest, GetPreKeyCountResponse};

use crate::api::{Auth, RequestError};
use crate::grpc::{GrpcServiceProvider, GrpcTestCase, log_and_send};
use crate::logging::Redact;

impl std::fmt::Display for Redact<GetPreKeyCountRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(GetPreKeyCountRequest {}) = self;
        f.debug_struct("GetPreKeyCountRequest").finish()
    }
}

/// Approximate counts of the one-time pre-keys stored for the authenticated
/// device, broken down by identity (ACI/PNI) and key kind (EC/KEM).
#[derive(Clone, Copy)]
#[cfg_attr(test, derive(PartialEq, Eq, Debug))]
pub struct PreKeyCounts {
    /// The approximate number of one-time EC pre-keys stored for the
    /// authenticated device and associated with the caller's ACI.
    pub aci_ec_pre_key_count: u32,
    /// The approximate number of one-time KEM pre-keys stored for the
    /// authenticated device and associated with the caller's ACI.
    pub aci_kem_pre_key_count: u32,
    /// The approximate number of one-time EC pre-keys stored for the
    /// authenticated device and associated with the caller's PNI.
    pub pni_ec_pre_key_count: u32,
    /// The approximate number of one-time KEM pre-keys stored for the
    /// authenticated device and associated with the caller's PNI.
    pub pni_kem_pre_key_count: u32,
}

impl<T: GrpcServiceProvider> Auth<T> {
    /// Retrieves an approximate count of the number of the various kinds of
    /// one-time pre-keys stored for the authenticated device.
    pub async fn get_pre_key_count(&self) -> Result<PreKeyCounts, RequestError<Infallible>> {
        let mut client = KeysClient::new(self.0.service());
        let request = GetPreKeyCountRequest {};
        let desc = Redact(&request).to_string();
        let GetPreKeyCountResponse {
            aci_ec_pre_key_count,
            aci_kem_pre_key_count,
            pni_ec_pre_key_count,
            pni_kem_pre_key_count,
        } = log_and_send("auth", &desc, || client.get_pre_key_count(request))
            .await?
            .into_inner();
        Ok(PreKeyCounts {
            aci_ec_pre_key_count,
            aci_kem_pre_key_count,
            pni_ec_pre_key_count,
            pni_kem_pre_key_count,
        })
    }
}

// Not cfg(test) so it can be accessed via bridging tests.
// These tests will get pruned via LTO tree shaking.
pub mod test_cases {
    use super::*;

    pub type GetPreKeyCountArgs = ();
    pub type GetPreKeyCountOut = PreKeyCounts;
    pub fn get_pre_key_count_test_cases() -> Vec<
        GrpcTestCase<
            GetPreKeyCountArgs,
            GetPreKeyCountRequest,
            GetPreKeyCountResponse,
            GetPreKeyCountOut,
        >,
    > {
        let method = "/org.signal.chat.keys.Keys/GetPreKeyCount";
        vec![
            GrpcTestCase {
                name: "zero counts".to_string(),
                method: method.to_string(),
                request: (),
                request_grpc: GetPreKeyCountRequest {},
                response_grpc: GetPreKeyCountResponse::default(),
                response: PreKeyCounts {
                    aci_ec_pre_key_count: 0,
                    aci_kem_pre_key_count: 0,
                    pni_ec_pre_key_count: 0,
                    pni_kem_pre_key_count: 0,
                },
            },
            // Distinct values for each field, to catch any transposition of
            // the four same-typed counts.
            GrpcTestCase {
                name: "distinct counts".to_string(),
                method: method.to_string(),
                request: (),
                request_grpc: GetPreKeyCountRequest {},
                response_grpc: GetPreKeyCountResponse {
                    aci_ec_pre_key_count: 42,
                    aci_kem_pre_key_count: 17,
                    pni_ec_pre_key_count: 33,
                    pni_kem_pre_key_count: 8,
                },
                response: PreKeyCounts {
                    aci_ec_pre_key_count: 42,
                    aci_kem_pre_key_count: 17,
                    pni_ec_pre_key_count: 33,
                    pni_kem_pre_key_count: 8,
                },
            },
        ]
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::grpc::testutil::run_tests;

    #[test]
    fn test_get_pre_key_count() {
        use test_cases::*;
        run_tests(
            get_pre_key_count_test_cases(),
            |chat: Auth<_>, ()| async move { chat.get_pre_key_count().await },
            |resp, result| assert_eq!(resp, result.expect("success")),
        );
    }
}
