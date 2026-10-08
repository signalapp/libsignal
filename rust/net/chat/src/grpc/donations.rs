//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;
use std::time::SystemTime;

use libsignal_net_grpc::proto::chat::donations::donations_client::DonationsClient;
use libsignal_net_grpc::proto::chat::donations::{
    CreateDonationPermitsRequest, CreateDonationPermitsResponse, RedeemReceiptRequest,
    RedeemReceiptResponse, redeem_receipt_response,
};
use libsignal_net_grpc::proto::chat::errors::{FailedPrecondition, FailedZkAuthentication};
use zkgroup::donations::{DonationPermit, DonationPermitRequestContext, DonationPermitResponse};
use zkgroup::receipts::ReceiptCredentialPresentation;

use crate::api::{Auth, RequestError};
use crate::grpc::{GrpcServiceProvider, log_and_send};
use crate::logging::Redact;

/// How a redeemed badge should appear on the account's profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BadgeVisibility {
    /// Don't make the badge visible. A new badge starts out hidden, and a badge the account already
    /// shows stays visible.
    DoNotSet,
    /// Make the badge visible on the profile.
    SetVisible,
    /// Make the badge visible on the profile as the primary badge.
    SetPrimary,
}

#[derive(Debug, displaydoc::Display)]
pub enum RedeemDonationReceiptFailure {
    /// Receipt credential presentation is invalid
    InvalidReceipt,
    /// Receipt was already redeemed
    AlreadyRedeemed,
}

impl std::fmt::Display for Redact<RedeemReceiptRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(RedeemReceiptRequest {
            receipt_credential_presentation: _,
            visible,
            primary,
        }) = self;
        f.debug_struct("RedeemReceiptRequest")
            .field("visible", visible)
            .field("primary", primary)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for Redact<CreateDonationPermitsRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self(CreateDonationPermitsRequest {
            donation_permits_request,
        }) = self;
        f.debug_struct("CreateDonationPermitsRequest")
            .field(
                "donation_permits_request.len()",
                &donation_permits_request.len(),
            )
            .finish()
    }
}

impl<T: GrpcServiceProvider> Auth<T> {
    /// Redeems a donation receipt to add the corresponding badge to the account.
    ///
    /// After this succeeds, the account has the badge until the receipt's expiration time.
    /// `visibility` controls whether it shows on the profile; see [`BadgeVisibility`].
    ///
    /// Redeeming the same receipt again for the same account succeeds. A receipt that was already
    /// redeemed by a different account fails with
    /// [`RedeemDonationReceiptFailure::AlreadyRedeemed`].
    pub async fn redeem_donation_receipt(
        &self,
        presentation: &ReceiptCredentialPresentation,
        visibility: BadgeVisibility,
    ) -> Result<(), RequestError<RedeemDonationReceiptFailure>> {
        let (visible, primary) = match visibility {
            BadgeVisibility::DoNotSet => (false, false),
            BadgeVisibility::SetVisible => (true, false),
            BadgeVisibility::SetPrimary => (true, true),
        };
        let request = RedeemReceiptRequest {
            receipt_credential_presentation: zkgroup::serialize(presentation),
            visible,
            primary,
        };
        let log_safe_description = Redact(&request).to_string();

        let mut donations_service = DonationsClient::new(self.0.service());
        let RedeemReceiptResponse { response } =
            log_and_send(Self::LOG_TAG, &log_safe_description, || {
                donations_service.redeem_receipt(request)
            })
            .await?
            .into_inner();

        match response.ok_or_else(|| RequestError::Unexpected {
            log_safe: "missing response".to_owned(),
        })? {
            redeem_receipt_response::Response::Success(()) => Ok(()),
            redeem_receipt_response::Response::FailedAuthentication(FailedZkAuthentication {
                description,
            }) => {
                log::warn!("invalid receipt: {description}");
                Err(RequestError::Other(
                    RedeemDonationReceiptFailure::InvalidReceipt,
                ))
            }
            redeem_receipt_response::Response::AlreadyRedeemed(FailedPrecondition {
                description,
            }) => {
                log::warn!("already redeemed: {description}");
                Err(RequestError::Other(
                    RedeemDonationReceiptFailure::AlreadyRedeemed,
                ))
            }
        }
    }

    /// Requests a batch of anonymous, single-use donation permits, one for each nonce in
    /// `request_context`.
    ///
    /// The server's response is verified against `server_params` before the permits are returned,
    /// in the same order as the nonces in `request_context`.
    ///
    /// The server rate-limits each account by the number of permits requested, not the number of
    /// requests. If the account doesn't have enough allowance left for the whole batch, nothing is
    /// issued or used up and this fails with [`RequestError::RetryLater`]. The retry delay is how
    /// long until the *full* batch would be allowed, so asking for fewer permits may succeed
    /// sooner, even right away. A batch larger than the server's maximum allowance will never
    /// succeed, no matter how long the caller waits.
    pub async fn create_donation_permits(
        &self,
        request_context: DonationPermitRequestContext,
        server_params: &zkgroup::ServerPublicParams,
    ) -> Result<Vec<DonationPermit>, RequestError<Infallible>> {
        let request = CreateDonationPermitsRequest {
            donation_permits_request: zkgroup::serialize(&request_context.request()),
        };
        let log_safe_description = Redact(&request).to_string();

        let mut donations_service = DonationsClient::new(self.0.service());
        let CreateDonationPermitsResponse {
            donation_permits_response,
        } = log_and_send(Self::LOG_TAG, &log_safe_description, || {
            donations_service.create_donation_permits(request)
        })
        .await?
        .into_inner();

        let zk_response = zkgroup::deserialize(&donation_permits_response).map_err(|e| {
            RequestError::Unexpected {
                log_safe: e.to_string(),
            }
        })?;
        request_context
            .receive(zk_response, server_params, SystemTime::now().into())
            .map_err(|e| RequestError::Unexpected {
                log_safe: e.to_string(),
            })
    }
}

pub mod test_cases {
    use std::num::NonZeroUsize;

    use zkgroup::donations::DonationPermitDerivedKeyPair;
    use zkgroup::{SECONDS_PER_DAY, Timestamp};

    use super::*;
    use crate::grpc::GrpcTestCase;
    use crate::grpc::test_case_util::{day_align, test_receipt_credential_presentation};

    #[derive(Clone)]
    pub struct RedeemDonationReceiptArgs {
        pub presentation: ReceiptCredentialPresentation,
        pub visibility: BadgeVisibility,
    }

    pub enum RedeemDonationReceiptOut {
        Success,
        InvalidReceipt,
        AlreadyRedeemed,
        UnexpectedError { contains: &'static str },
    }

    pub fn redeem_donation_receipt_test_cases() -> Vec<
        GrpcTestCase<
            RedeemDonationReceiptArgs,
            RedeemReceiptRequest,
            RedeemReceiptResponse,
            RedeemDonationReceiptOut,
        >,
    > {
        let method = "/org.signal.chat.donations.Donations/RedeemReceipt";
        let presentation = test_receipt_credential_presentation();

        let case = |name: &str,
                    visibility: BadgeVisibility,
                    (visible, primary): (bool, bool),
                    response_grpc: Option<redeem_receipt_response::Response>,
                    response| GrpcTestCase {
            name: name.to_owned(),
            method: method.into(),
            request: RedeemDonationReceiptArgs {
                presentation: presentation.clone(),
                visibility,
            },
            request_grpc: RedeemReceiptRequest {
                receipt_credential_presentation: zkgroup::serialize(&presentation),
                visible,
                primary,
            },
            response_grpc: RedeemReceiptResponse {
                response: response_grpc,
            },
            response,
        };

        vec![
            case(
                "success, do not set",
                BadgeVisibility::DoNotSet,
                (false, false),
                Some(redeem_receipt_response::Response::Success(())),
                RedeemDonationReceiptOut::Success,
            ),
            case(
                "success, set visible",
                BadgeVisibility::SetVisible,
                (true, false),
                Some(redeem_receipt_response::Response::Success(())),
                RedeemDonationReceiptOut::Success,
            ),
            case(
                "success, set primary",
                BadgeVisibility::SetPrimary,
                (true, true),
                Some(redeem_receipt_response::Response::Success(())),
                RedeemDonationReceiptOut::Success,
            ),
            case(
                "invalid receipt",
                BadgeVisibility::SetVisible,
                (true, false),
                Some(redeem_receipt_response::Response::FailedAuthentication(
                    FailedZkAuthentication {
                        description: "bad!".to_owned(),
                    },
                )),
                RedeemDonationReceiptOut::InvalidReceipt,
            ),
            case(
                "already redeemed",
                BadgeVisibility::SetVisible,
                (true, false),
                Some(redeem_receipt_response::Response::AlreadyRedeemed(
                    FailedPrecondition {
                        description: "taken".to_owned(),
                    },
                )),
                RedeemDonationReceiptOut::AlreadyRedeemed,
            ),
            case(
                "missing response",
                BadgeVisibility::SetVisible,
                (true, false),
                None,
                RedeemDonationReceiptOut::UnexpectedError {
                    contains: "missing response",
                },
            ),
        ]
    }

    #[derive(Clone)]
    pub struct CreateDonationPermitsArgs {
        pub request_context: DonationPermitRequestContext,
        pub server_params: zkgroup::ServerPublicParams,
    }

    pub enum CreateDonationPermitsOut {
        Success(Vec<DonationPermit>),
        UnexpectedError { contains: &'static str },
    }

    pub fn create_donation_permits_test_cases() -> Vec<
        GrpcTestCase<
            CreateDonationPermitsArgs,
            CreateDonationPermitsRequest,
            CreateDonationPermitsResponse,
            CreateDonationPermitsOut,
        >,
    > {
        let method = "/org.signal.chat.donations.Donations/CreateDonationPermits";
        let server_secret_params =
            zkgroup::ServerSecretParams::generate([1; zkgroup::RANDOMNESS_LEN]);
        let server_params = server_secret_params.get_public_params();
        let request_context = DonationPermitRequestContext::new(
            NonZeroUsize::new(3).expect("non-zero"),
            [2; zkgroup::RANDOMNESS_LEN],
        );

        let now: Timestamp = SystemTime::now().into();
        let issue = |request_context: &DonationPermitRequestContext,
                     server_secret_params: &zkgroup::ServerSecretParams,
                     expiration: Timestamp| {
            let key_pair =
                DonationPermitDerivedKeyPair::for_expiration(expiration, server_secret_params);
            DonationPermitResponse::issue(
                request_context.request(),
                &key_pair,
                [3; zkgroup::RANDOMNESS_LEN],
            )
        };

        let zk_response = issue(
            &request_context,
            &server_secret_params,
            DonationPermitResponse::default_expiration(now),
        );
        let permits = request_context
            .clone()
            .receive(zk_response.clone(), &server_params, now)
            .expect("valid");

        let case =
            |name: &str, zk_response: Option<&DonationPermitResponse>, response| GrpcTestCase {
                name: name.to_owned(),
                method: method.into(),
                request: CreateDonationPermitsArgs {
                    request_context: request_context.clone(),
                    server_params: server_params.clone(),
                },
                request_grpc: CreateDonationPermitsRequest {
                    donation_permits_request: zkgroup::serialize(&request_context.request()),
                },
                response_grpc: CreateDonationPermitsResponse {
                    donation_permits_response: zk_response
                        .map(zkgroup::serialize)
                        .unwrap_or_default(),
                },
                response,
            };

        vec![
            case(
                "success",
                Some(&zk_response),
                CreateDonationPermitsOut::Success(permits),
            ),
            case(
                "empty response",
                None,
                CreateDonationPermitsOut::UnexpectedError {
                    contains: "Failed to deserialize",
                },
            ),
            case(
                "wrong issuing key",
                Some(&issue(
                    &request_context,
                    &zkgroup::ServerSecretParams::generate([4; zkgroup::RANDOMNESS_LEN]),
                    DonationPermitResponse::default_expiration(now),
                )),
                CreateDonationPermitsOut::UnexpectedError {
                    contains: "Verification failure",
                },
            ),
            case(
                "wrong number of permits",
                Some(&issue(
                    &DonationPermitRequestContext::new(
                        NonZeroUsize::new(2).expect("non-zero"),
                        [2; zkgroup::RANDOMNESS_LEN],
                    ),
                    &server_secret_params,
                    DonationPermitResponse::default_expiration(now),
                )),
                CreateDonationPermitsOut::UnexpectedError {
                    contains: "Verification failure",
                },
            ),
            case(
                "expiration too far in the future",
                Some(&issue(
                    &request_context,
                    &server_secret_params,
                    Timestamp::from_epoch_seconds(
                        day_align(now.epoch_seconds()) + 9 * SECONDS_PER_DAY,
                    ),
                )),
                CreateDonationPermitsOut::UnexpectedError {
                    contains: "Verification failure",
                },
            ),
            case(
                "expiration not day-aligned",
                Some(&issue(
                    &request_context,
                    &server_secret_params,
                    Timestamp::from_epoch_seconds(
                        DonationPermitResponse::default_expiration(now).epoch_seconds() + 1,
                    ),
                )),
                CreateDonationPermitsOut::UnexpectedError {
                    contains: "Verification failure",
                },
            ),
        ]
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;

    use super::test_cases::*;
    use super::*;
    use crate::grpc::testutil::run_tests;

    #[test]
    fn test_redeem_donation_receipt() {
        run_tests(
            redeem_donation_receipt_test_cases(),
            |chat: Auth<_>,
             RedeemDonationReceiptArgs {
                 presentation,
                 visibility,
             }| async move {
                chat.redeem_donation_receipt(&presentation, visibility)
                    .await
            },
            |expected, actual| match expected {
                RedeemDonationReceiptOut::Success => actual.expect("success"),
                RedeemDonationReceiptOut::InvalidReceipt => assert_matches!(
                    actual,
                    Err(RequestError::Other(
                        RedeemDonationReceiptFailure::InvalidReceipt
                    ))
                ),
                RedeemDonationReceiptOut::AlreadyRedeemed => assert_matches!(
                    actual,
                    Err(RequestError::Other(
                        RedeemDonationReceiptFailure::AlreadyRedeemed
                    ))
                ),
                RedeemDonationReceiptOut::UnexpectedError { contains } => assert_matches!(
                    actual,
                    Err(RequestError::Unexpected { log_safe }) if log_safe.contains(contains)
                ),
            },
        );
    }

    #[test]
    fn test_create_donation_permits() {
        run_tests(
            create_donation_permits_test_cases(),
            |chat: Auth<_>,
             CreateDonationPermitsArgs {
                 request_context,
                 server_params,
             }| async move {
                chat.create_donation_permits(request_context, &server_params)
                    .await
            },
            |expected, actual| match expected {
                CreateDonationPermitsOut::Success(expected_permits) => assert_eq!(
                    Vec::from_iter(expected_permits.iter().map(zkgroup::serialize)),
                    Vec::from_iter(actual.expect("success").iter().map(zkgroup::serialize)),
                ),
                CreateDonationPermitsOut::UnexpectedError { contains } => {
                    assert_matches!(
                        actual,
                        Err(RequestError::Unexpected { log_safe })
                        if log_safe.contains(contains)
                    );
                }
            },
        );
    }
}
