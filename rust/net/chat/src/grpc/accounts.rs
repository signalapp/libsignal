//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use libsignal_account_keys::SvrKey;
use libsignal_net_grpc::proto::chat::account::accounts_client::AccountsClient;
use libsignal_net_grpc::proto::chat::account::{
    ClearRegistrationLockRequest, ClearRegistrationLockResponse,
    SetDiscoverableByPhoneNumberRequest, SetDiscoverableByPhoneNumberResponse,
    SetRegistrationLockRequest, SetRegistrationLockResponse,
};

use crate::api::{Auth, RequestError};
use crate::grpc::{GrpcServiceProvider, GrpcTestCase, log_and_send};
use crate::logging::Redact;

impl std::fmt::Display for Redact<SetRegistrationLockRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SetRegistrationLockRequest { registration_lock }) = self;
        f.debug_struct("SetRegistrationLockRequest")
            .field("registration_lock_len", &registration_lock.len())
            .finish()
    }
}

impl std::fmt::Display for Redact<ClearRegistrationLockRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(ClearRegistrationLockRequest {}) = self;
        f.debug_struct("ClearRegistrationLockRequest").finish()
    }
}

impl std::fmt::Display for Redact<SetDiscoverableByPhoneNumberRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(SetDiscoverableByPhoneNumberRequest {
            discoverable_by_phone_number,
        }) = self;
        f.debug_struct("SetDiscoverableByPhoneNumberRequest")
            .field("discoverable", discoverable_by_phone_number)
            .finish()
    }
}

impl<T: GrpcServiceProvider> Auth<T> {
    /// Sets the registration lock for the authenticated account, given the account's SVR key.
    ///
    /// libsignal derives the registration lock token from the SVR key (see
    /// [`SvrKey::derive_registration_lock`]) and sends only that derived token; the SVR key itself
    /// never leaves the device.
    ///
    /// While the registration lock is set, re-registering the account's phone
    /// number requires proving knowledge of the token.
    ///
    /// Only the account's primary device may set a registration lock. Removing
    /// a registration lock is a separate operation; see
    /// [`Self::clear_registration_lock`].
    pub async fn set_registration_lock(
        &self,
        svr_key: SvrKey,
    ) -> Result<(), RequestError<Infallible>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = SetRegistrationLockRequest {
            registration_lock: svr_key.derive_registration_lock().to_vec(),
        };
        let desc = Redact(&request).to_string();
        let SetRegistrationLockResponse {} =
            log_and_send("auth", &desc, || client.set_registration_lock(request))
                .await?
                .into_inner();
        Ok(())
    }

    /// Removes any registration lock from the authenticated account.
    ///
    /// This also succeeds if the account has no registration lock set, so a
    /// caller retrying a removal sees the same result as the original call.
    ///
    /// Only the account's primary device may clear a registration lock; the
    /// server rejects calls from linked devices as a programmer error,
    /// surfaced as [`RequestError::Unexpected`].
    pub async fn clear_registration_lock(&self) -> Result<(), RequestError<Infallible>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = ClearRegistrationLockRequest {};
        let desc = Redact(&request).to_string();
        let ClearRegistrationLockResponse {} =
            log_and_send("auth", &desc, || client.clear_registration_lock(request))
                .await?
                .into_inner();
        Ok(())
    }

    /// Sets whether the authenticated account may be discovered by phone number via the Contact
    /// Discovery Service (CDS).
    ///
    /// If `false`, other users must discover this account by other means (e.g. by username).
    pub async fn set_discoverable_by_phone_number(
        &self,
        discoverable: bool,
    ) -> Result<(), RequestError<Infallible>> {
        let mut client = AccountsClient::new(self.0.service());
        let request = SetDiscoverableByPhoneNumberRequest {
            discoverable_by_phone_number: discoverable,
        };
        let desc = Redact(&request).to_string();
        let SetDiscoverableByPhoneNumberResponse {} = log_and_send("auth", &desc, || {
            client.set_discoverable_by_phone_number(request)
        })
        .await?
        .into_inner();
        Ok(())
    }
}

// Not cfg(test) so it can be accessed via bridging tests.
// These tests will get pruned via LTO tree shaking.
pub mod test_cases {
    use super::*;

    // The request crosses the bridge as the raw 32-byte SVR key; libsignal derives the registration
    // lock token from it, so the expected gRPC request carries the derived token.
    pub fn set_registration_lock_test_cases()
    -> Vec<GrpcTestCase<[u8; 32], SetRegistrationLockRequest, SetRegistrationLockResponse, ()>>
    {
        let method = "/org.signal.chat.account.Accounts/SetRegistrationLock";
        let svr_key = [0x42; 32];
        vec![GrpcTestCase {
            name: "success".to_string(),
            method: method.to_string(),
            request: svr_key,
            request_grpc: SetRegistrationLockRequest {
                registration_lock: const_str::hex!(
                    "45b43bb819964ad8ba1c7bcb42a3175eeaf7dd8d2f95728f811517c20dfe72e0"
                )
                .to_vec(),
            },
            response_grpc: SetRegistrationLockResponse {},
            response: (),
        }]
    }

    pub fn clear_registration_lock_test_cases()
    -> Vec<GrpcTestCase<(), ClearRegistrationLockRequest, ClearRegistrationLockResponse, ()>> {
        let method = "/org.signal.chat.account.Accounts/ClearRegistrationLock";
        vec![GrpcTestCase {
            name: "success".to_string(),
            method: method.to_string(),
            request: (),
            request_grpc: ClearRegistrationLockRequest {},
            response_grpc: ClearRegistrationLockResponse {},
            response: (),
        }]
    }

    pub fn set_discoverable_by_phone_number_test_cases() -> Vec<
        GrpcTestCase<
            bool,
            SetDiscoverableByPhoneNumberRequest,
            SetDiscoverableByPhoneNumberResponse,
            (),
        >,
    > {
        let method = "/org.signal.chat.account.Accounts/SetDiscoverableByPhoneNumber";
        [true, false]
            .into_iter()
            .map(|discoverable| GrpcTestCase {
                name: if discoverable {
                    "discoverable".to_string()
                } else {
                    "not discoverable".to_string()
                },
                method: method.to_string(),
                request: discoverable,
                request_grpc: SetDiscoverableByPhoneNumberRequest {
                    discoverable_by_phone_number: discoverable,
                },
                response_grpc: SetDiscoverableByPhoneNumberResponse {},
                response: (),
            })
            .collect()
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;

    use super::*;
    use crate::grpc::testutil::run_tests;

    #[test]
    fn test_set_registration_lock() {
        use test_cases::*;
        run_tests(
            set_registration_lock_test_cases(),
            |chat: Auth<_>, svr_key: [u8; 32]| async move {
                chat.set_registration_lock(SvrKey::new(svr_key)).await
            },
            |(), result| assert_matches!(result, Ok(())),
        );
    }

    #[test]
    fn test_clear_registration_lock() {
        use test_cases::*;
        run_tests(
            clear_registration_lock_test_cases(),
            |chat: Auth<_>, ()| async move { chat.clear_registration_lock().await },
            |(), result| assert_matches!(result, Ok(())),
        );
    }

    #[test]
    fn test_set_discoverable_by_phone_number() {
        use test_cases::*;
        run_tests(
            set_discoverable_by_phone_number_test_cases(),
            |chat: Auth<_>, discoverable: bool| async move {
                chat.set_discoverable_by_phone_number(discoverable).await
            },
            |(), result| assert_matches!(result, Ok(())),
        );
    }
}
