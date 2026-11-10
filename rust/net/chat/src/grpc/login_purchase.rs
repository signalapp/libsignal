//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::convert::Infallible;

use libsignal_net_grpc::proto::chat::errors::{FailedPrecondition, NotFound};
use libsignal_net_grpc::proto::chat::purchase::create_login_receipt_credential_response::Response as CreateLoginReceiptCredentialResponseEnum;
use libsignal_net_grpc::proto::chat::purchase::login_purchase_client::LoginPurchaseClient;
use libsignal_net_grpc::proto::chat::purchase::{
    ChargeFailure as GrpcChargeFailure, CreateLoginReceiptCredentialRequest,
    PaymentProvider as GrpcPaymentProvider,
};
use libsignal_protocol::Timestamp;
use strum::VariantArray;
use zkgroup::receipts::{
    ReceiptCredential, ReceiptCredentialRequestContext, ReceiptCredentialResponse,
};
use zkgroup::{ReceiptLevel, SECONDS_PER_DAY, ServerPublicParams, ZkGroupVerificationFailure};

use crate::api::purchase::{ChargeFailure, PaymentProvider};
use crate::api::{RequestError, Unauth};
use crate::grpc::{GrpcServiceProvider, log_and_send};
use crate::logging::Redact;

impl From<PaymentProvider> for GrpcPaymentProvider {
    fn from(value: PaymentProvider) -> Self {
        match value {
            PaymentProvider::GooglePlayBilling => Self::GooglePlayBilling,
            PaymentProvider::AppleAppStore => Self::AppleAppStore,
            PaymentProvider::Stripe => Self::Stripe,
            PaymentProvider::Braintree => Self::Braintree,
        }
    }
}

impl TryFrom<GrpcPaymentProvider> for PaymentProvider {
    type Error = RequestError<Infallible>;

    fn try_from(value: GrpcPaymentProvider) -> Result<Self, Self::Error> {
        match value {
            GrpcPaymentProvider::Unknown => Err(RequestError::Unexpected {
                log_safe: "Unknown returned payment provider".into(),
            }),
            GrpcPaymentProvider::Stripe => Ok(PaymentProvider::Stripe),
            GrpcPaymentProvider::Braintree => Ok(PaymentProvider::Braintree),
            GrpcPaymentProvider::GooglePlayBilling => Ok(PaymentProvider::GooglePlayBilling),
            GrpcPaymentProvider::AppleAppStore => Ok(PaymentProvider::AppleAppStore),
        }
    }
}

impl TryFrom<GrpcChargeFailure> for ChargeFailure {
    type Error = RequestError<Infallible>;

    fn try_from(value: GrpcChargeFailure) -> Result<Self, Self::Error> {
        let GrpcChargeFailure {
            processor,
            code,
            message,
            outcome_network_status,
            outcome_reason,
            outcome_type,
        } = value;
        Ok(ChargeFailure {
            processor: GrpcPaymentProvider::try_from(processor)
                .unwrap_or_default()
                .try_into()?,
            code,
            message,
            outcome_network_status,
            outcome_reason,
            outcome_type,
        })
    }
}

#[derive(Clone, Debug, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum ReceiptCredentialError {
    /// The purchase is still pending with the payment provider. The client may retry later.
    PaymentStillProcessing,
    /// The purchase did not complete successfully.
    PaymentRequired {
        charge_failure: Option<Box<ChargeFailure>>,
    },
    /// The payment provider has no purchase with the provided purchase_identifier
    PaymentNotFound,
    /// The purchase was already redeemed for a receipt credential using a different request
    ReceiptAlreadyIssued,
}

impl std::fmt::Display for Redact<CreateLoginReceiptCredentialRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Redact(CreateLoginReceiptCredentialRequest {
            processor,
            purchase_identifier,
            receipt_credential_request,
        }) = self;
        f.debug_struct("CreateLoginReceiptCredentialRequest")
            .field("processor", processor)
            .field("purchase_identifier.len()", &purchase_identifier.len())
            .field(
                "receipt_credential_request.len()",
                &receipt_credential_request.len(),
            )
            .finish()
    }
}

fn unsigned_distance(x: u64, y: u64) -> u64 {
    x.max(y) - x.min(y)
}

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq, VariantArray)]
pub enum LoginReceiptLevel {
    #[default]
    Normal = 300,
    Sandbox = 301,
}
impl LoginReceiptLevel {
    fn expiration_days(&self) -> u64 {
        match self {
            LoginReceiptLevel::Normal => EXPIRATION_DAYS_NORMAL,
            LoginReceiptLevel::Sandbox => EXPIRATION_DAYS_SANDBOX,
        }
    }
}

const EXPIRATION_DAYS_NORMAL: u64 = 5 * 366; // ~ 5 years
const EXPIRATION_DAYS_SANDBOX: u64 = 2;
const EXPIRATION_DAYS_LENIENCY: u64 = 7;

const UNEXPECTED_RECEIPT_LEVEL: &str = "Invalid receipt: level";
const UNEXPECTED_CANT_RECV: &str = "Failed to receive receipt credential response";
const UNEXPECTED_EXPIRATION_OUT_OF_RANGE: &str =
    "Invalid receipt: expiration time outside of range";

impl<T: GrpcServiceProvider> Unauth<T> {
    /// Obtain a ZK receipt credential for a completed one-time login payment.
    ///
    /// The receipt credential can then be presented at registration.
    ///
    /// Subsequent retries to create a login credential for the same purchase_identifier must use
    /// an identical `receipt_credential_request_context`.
    pub async fn create_login_receipt_credential(
        &self,
        payment_processor: PaymentProvider,
        purchase_identifier: String,
        receipt_credential_request_context: &ReceiptCredentialRequestContext,
        server_params: &ServerPublicParams,
        purchase_time: Timestamp,
        expected_level: LoginReceiptLevel,
    ) -> Result<ReceiptCredential, RequestError<ReceiptCredentialError>> {
        let mut client = LoginPurchaseClient::new(self.0.service());
        let request = CreateLoginReceiptCredentialRequest {
            processor: GrpcPaymentProvider::from(payment_processor).into(),
            purchase_identifier,
            receipt_credential_request: zkgroup::serialize(
                &receipt_credential_request_context.get_request(),
            ),
        };
        let desc = Redact(&request).to_string();
        match log_and_send(Self::LOG_TAG, &desc, || {
            client.create_login_receipt_credential(request)
        })
        .await?
        .into_inner()
        .response
        .ok_or_else(|| RequestError::Unexpected {
            log_safe: "Missing response".to_string(),
        })? {
            CreateLoginReceiptCredentialResponseEnum::Result(result) => {
                let response: ReceiptCredentialResponse =
                    zkgroup::deserialize(&result.receipt_credential_response).map_err(|_| {
                        RequestError::Unexpected {
                            log_safe: "Can't deserialize receipt credential response".into(),
                        }
                    })?;
                let out = server_params
                    .receive_receipt_credential(receipt_credential_request_context, &response)
                    .map_err(|ZkGroupVerificationFailure| RequestError::Unexpected {
                        log_safe: UNEXPECTED_CANT_RECV.into(),
                    })?;
                if out.get_receipt_level() != expected_level as ReceiptLevel {
                    return Err(RequestError::Unexpected {
                        log_safe: UNEXPECTED_RECEIPT_LEVEL.into(),
                    });
                }
                // This check is already performed in receive_receipt_credential(), but we do it
                // again just to be safe.
                if !out
                    .get_receipt_expiration_time()
                    .epoch_seconds()
                    .is_multiple_of(SECONDS_PER_DAY)
                {
                    return Err(RequestError::Unexpected {
                        log_safe: "Invalid receipt: expiration time".into(),
                    });
                }
                let purchase_time_seconds = purchase_time.epoch_millis() / 1000;
                if unsigned_distance(
                    out.get_receipt_expiration_time().epoch_seconds(),
                    purchase_time_seconds + (expected_level.expiration_days() * SECONDS_PER_DAY),
                ) > EXPIRATION_DAYS_LENIENCY * SECONDS_PER_DAY
                {
                    return Err(RequestError::Unexpected {
                        log_safe: UNEXPECTED_EXPIRATION_OUT_OF_RANGE.into(),
                    });
                }
                Ok(out)
            }
            CreateLoginReceiptCredentialResponseEnum::PaymentStillProcessing(
                FailedPrecondition { description },
            ) => {
                log::warn!("CreateLoginReceiptCredentialResponse error: {description}");
                Err(RequestError::Other(
                    ReceiptCredentialError::PaymentStillProcessing,
                ))
            }
            CreateLoginReceiptCredentialResponseEnum::PaymentRequired(payment_required) => Err(
                RequestError::Other(ReceiptCredentialError::PaymentRequired {
                    charge_failure: payment_required
                        .charge_failure
                        .map(|charge_failure| Ok(Box::new(charge_failure.try_into()?)))
                        .transpose()
                        .map_err(RequestError::with_other)?,
                }),
            ),
            CreateLoginReceiptCredentialResponseEnum::PaymentNotFound(NotFound {}) => {
                Err(RequestError::Other(ReceiptCredentialError::PaymentNotFound))
            }
            CreateLoginReceiptCredentialResponseEnum::ReceiptAlreadyIssued(
                FailedPrecondition { description },
            ) => {
                log::warn!(
                    "CreateLoginReceiptCredentialResponse error: ReceiptAlreadyIssued {description}"
                );
                Err(RequestError::Other(
                    ReceiptCredentialError::ReceiptAlreadyIssued,
                ))
            }
        }
    }
}

pub mod test_cases {
    use libsignal_net_grpc::proto::chat::errors::{FailedPrecondition, NotFound};
    use libsignal_net_grpc::proto::chat::purchase::CreateLoginReceiptCredentialResponse;
    use libsignal_net_grpc::proto::chat::purchase::create_login_receipt_credential_response::CreateLoginReceiptCredentialResult;
    use zkgroup::{SECONDS_PER_DAY, ServerSecretParams};

    use super::*;
    use crate::grpc::GrpcTestCase;
    use crate::grpc::test_case_util::day_align;

    #[derive(Clone)]
    pub struct CreateLoginReceiptCredentialArgs {
        pub payment_processor: PaymentProvider,
        pub purchase_identifier: String,
        pub receipt_credential_request_context: ReceiptCredentialRequestContext,
        pub server_params: ServerPublicParams,
        pub purchase_time: Timestamp,
        pub expected_level: LoginReceiptLevel,
    }
    #[allow(clippy::large_enum_variant)]
    pub enum CreateLoginReceiptCredentialOut {
        Success(ReceiptCredential),
        UnexpectedError { contains: String },
        ExplicitError(ReceiptCredentialError),
    }
    pub fn create_login_receipt_credential_test_cases() -> Vec<
        GrpcTestCase<
            CreateLoginReceiptCredentialArgs,
            CreateLoginReceiptCredentialRequest,
            CreateLoginReceiptCredentialResponse,
            CreateLoginReceiptCredentialOut,
        >,
    > {
        let server_secret_params = ServerSecretParams::generate([0x01; _]);
        let server_params = server_secret_params.get_public_params();
        let ctx = server_params.create_receipt_credential_request_context([0x02; _], [0x04; _]);
        let purchase_time = Timestamp::from_epoch_millis(1787260006799);
        let method = "/org.signal.chat.purchase.LoginPurchase/CreateLoginReceiptCredential";
        let purchase_identifier =
            "The string, herein described, shall uniquely identify a payment".to_string();
        let issue_receipt = |level, expiration| {
            server_secret_params.issue_receipt_credential(
                [0x5; _],
                &ctx.get_request(),
                expiration,
                level,
            )
        };
        let make_request = |payment_processor, expected_level| CreateLoginReceiptCredentialArgs {
            payment_processor,
            purchase_identifier: purchase_identifier.clone(),
            receipt_credential_request_context: ctx.clone(),
            server_params: server_params.clone(),
            purchase_time,
            expected_level,
        };
        let make_grpc_request =
            |grpc_payment_processor: GrpcPaymentProvider| CreateLoginReceiptCredentialRequest {
                processor: grpc_payment_processor.into(),
                purchase_identifier: purchase_identifier.clone(),
                receipt_credential_request: zkgroup::serialize(&ctx.get_request()),
            };
        let gplay_request = make_request(PaymentProvider::GooglePlayBilling, Default::default());
        let gplay_grpc_request = make_grpc_request(GrpcPaymentProvider::GooglePlayBilling);
        let mut test_cases = Vec::new();
        let purchase_time_seconds = purchase_time.epoch_millis() / 1000;
        for &level in LoginReceiptLevel::VARIANTS {
            for (payment_processor, grpc_payment_processor) in [
                (
                    PaymentProvider::GooglePlayBilling,
                    GrpcPaymentProvider::GooglePlayBilling,
                ),
                (
                    PaymentProvider::AppleAppStore,
                    GrpcPaymentProvider::AppleAppStore,
                ),
                (PaymentProvider::Stripe, GrpcPaymentProvider::Stripe),
                (PaymentProvider::Braintree, GrpcPaymentProvider::Braintree),
            ] {
                let receipt_response = issue_receipt(
                    level as ReceiptLevel,
                    zkgroup::Timestamp::from_epoch_seconds(day_align(
                        purchase_time_seconds + (level.expiration_days() - 1) * SECONDS_PER_DAY,
                    )),
                );
                test_cases.push(GrpcTestCase {
                    name: format!("{level:?} Success {payment_processor:?}"),
                    method: method.into(),
                    request: make_request(payment_processor, level),
                    request_grpc: make_grpc_request(grpc_payment_processor),
                    response_grpc: CreateLoginReceiptCredentialResponse {
                        response: Some(CreateLoginReceiptCredentialResponseEnum::Result(
                            CreateLoginReceiptCredentialResult {
                                receipt_credential_response: zkgroup::serialize(&receipt_response),
                            },
                        )),
                    },
                    response: CreateLoginReceiptCredentialOut::Success(
                        server_params
                            .receive_receipt_credential(&ctx, &receipt_response)
                            .expect("can generate"),
                    ),
                });
            }
            {
                let receipt_response = issue_receipt(
                    level as ReceiptLevel,
                    zkgroup::Timestamp::from_epoch_seconds(
                        day_align(
                            purchase_time_seconds + (level.expiration_days() - 2) * SECONDS_PER_DAY,
                        ) + 1,
                    ),
                );
                test_cases.push(GrpcTestCase {
                    name: format!("{level:?} Misaligned expiration"),
                    method: method.into(),
                    request: make_request(PaymentProvider::GooglePlayBilling, level),
                    request_grpc: make_grpc_request(GrpcPaymentProvider::GooglePlayBilling),
                    response_grpc: CreateLoginReceiptCredentialResponse {
                        response: Some(CreateLoginReceiptCredentialResponseEnum::Result(
                            CreateLoginReceiptCredentialResult {
                                receipt_credential_response: zkgroup::serialize(&receipt_response),
                            },
                        )),
                    },
                    response: CreateLoginReceiptCredentialOut::UnexpectedError {
                        contains: UNEXPECTED_CANT_RECV.into(),
                    },
                });
            }
            for expiration in [
                day_align(purchase_time_seconds) - (EXPIRATION_DAYS_LENIENCY + 1) * SECONDS_PER_DAY,
                day_align(purchase_time_seconds)
                    + (level.expiration_days() + EXPIRATION_DAYS_LENIENCY + 1) * SECONDS_PER_DAY,
            ] {
                let receipt_response = issue_receipt(
                    level as ReceiptLevel,
                    zkgroup::Timestamp::from_epoch_seconds(expiration),
                );
                test_cases.push(GrpcTestCase {
                    name: format!("{level:?} Out of bounds expiration {expiration:?}"),
                    method: method.into(),
                    request: make_request(PaymentProvider::GooglePlayBilling, level),
                    request_grpc: make_grpc_request(GrpcPaymentProvider::GooglePlayBilling),
                    response_grpc: CreateLoginReceiptCredentialResponse {
                        response: Some(CreateLoginReceiptCredentialResponseEnum::Result(
                            CreateLoginReceiptCredentialResult {
                                receipt_credential_response: zkgroup::serialize(&receipt_response),
                            },
                        )),
                    },
                    response: CreateLoginReceiptCredentialOut::UnexpectedError {
                        contains: UNEXPECTED_EXPIRATION_OUT_OF_RANGE.into(),
                    },
                });
            }
        }
        // Unexpected Errors
        for (requested_level, responded_level) in [
            (LoginReceiptLevel::Normal, LoginReceiptLevel::Sandbox),
            (LoginReceiptLevel::Sandbox, LoginReceiptLevel::Normal),
        ] {
            let receipt_response = issue_receipt(
                responded_level as ReceiptLevel,
                zkgroup::Timestamp::from_epoch_seconds(day_align(
                    purchase_time_seconds
                        + (requested_level.expiration_days() - 1) * SECONDS_PER_DAY,
                )),
            );
            test_cases.push(GrpcTestCase {
                name: "Level gets checked".into(),
                method: method.into(),
                request: make_request(PaymentProvider::GooglePlayBilling, requested_level),
                request_grpc: make_grpc_request(GrpcPaymentProvider::GooglePlayBilling),
                response_grpc: CreateLoginReceiptCredentialResponse {
                    response: Some(CreateLoginReceiptCredentialResponseEnum::Result(
                        CreateLoginReceiptCredentialResult {
                            receipt_credential_response: zkgroup::serialize(&receipt_response),
                        },
                    )),
                },
                response: CreateLoginReceiptCredentialOut::UnexpectedError {
                    contains: UNEXPECTED_RECEIPT_LEVEL.into(),
                },
            });
        }
        // Simple Error cases
        for (nice_error, grpc_error) in [
            (
                ReceiptCredentialError::PaymentStillProcessing,
                CreateLoginReceiptCredentialResponseEnum::PaymentStillProcessing(
                    FailedPrecondition {
                        description: "error".into(),
                    },
                ),
            ),
            (
                ReceiptCredentialError::PaymentNotFound,
                CreateLoginReceiptCredentialResponseEnum::PaymentNotFound(NotFound {}),
            ),
            (
                ReceiptCredentialError::ReceiptAlreadyIssued,
                CreateLoginReceiptCredentialResponseEnum::ReceiptAlreadyIssued(
                    FailedPrecondition {
                        description: "error".into(),
                    },
                ),
            ),
        ] {
            test_cases.push(GrpcTestCase {
                name: format!("Error {nice_error:?}"),
                method: method.to_string(),
                request: gplay_request.clone(),
                request_grpc: gplay_grpc_request.clone(),
                response_grpc: CreateLoginReceiptCredentialResponse {
                    response: Some(grpc_error),
                },
                response: CreateLoginReceiptCredentialOut::ExplicitError(nice_error),
            });
        }
        // Payment Required error cases
        test_cases.push(GrpcTestCase {
            name: "Payment Required: None".into(),
            method: method.to_string(),
            request: gplay_request.clone(),
            request_grpc: gplay_grpc_request.clone(),
            response_grpc: CreateLoginReceiptCredentialResponse {
                response: Some(CreateLoginReceiptCredentialResponseEnum::PaymentRequired(
                    libsignal_net_grpc::proto::chat::purchase::PaymentRequired {
                        charge_failure: None,
                    },
                )),
            },
            response: CreateLoginReceiptCredentialOut::ExplicitError(
                ReceiptCredentialError::PaymentRequired {
                    charge_failure: None,
                },
            ),
        });
        test_cases.push(GrpcTestCase {
            name: "Payment Required: None fields".into(),
            method: method.to_string(),
            request: gplay_request.clone(),
            request_grpc: gplay_grpc_request.clone(),
            response_grpc: CreateLoginReceiptCredentialResponse {
                response: Some(CreateLoginReceiptCredentialResponseEnum::PaymentRequired(
                    libsignal_net_grpc::proto::chat::purchase::PaymentRequired {
                        charge_failure: Some(GrpcChargeFailure {
                            processor: GrpcPaymentProvider::GooglePlayBilling.into(),
                            code: "code".into(),
                            message: "message".into(),
                            outcome_network_status: None,
                            outcome_reason: None,
                            outcome_type: None,
                        }),
                    },
                )),
            },
            response: CreateLoginReceiptCredentialOut::ExplicitError(
                ReceiptCredentialError::PaymentRequired {
                    charge_failure: Some(Box::new(ChargeFailure {
                        processor: PaymentProvider::GooglePlayBilling,
                        code: "code".into(),
                        message: "message".into(),
                        outcome_network_status: None,
                        outcome_reason: None,
                        outcome_type: None,
                    })),
                },
            ),
        });
        test_cases.push(GrpcTestCase {
            name: "Payment Required: Some fields".into(),
            method: method.to_string(),
            request: gplay_request.clone(),
            request_grpc: gplay_grpc_request.clone(),
            response_grpc: CreateLoginReceiptCredentialResponse {
                response: Some(CreateLoginReceiptCredentialResponseEnum::PaymentRequired(
                    libsignal_net_grpc::proto::chat::purchase::PaymentRequired {
                        charge_failure: Some(GrpcChargeFailure {
                            processor: GrpcPaymentProvider::GooglePlayBilling.into(),
                            code: "code".into(),
                            message: "message".into(),
                            outcome_network_status: Some("ons".into()),
                            outcome_reason: Some("or".into()),
                            outcome_type: Some("ot".into()),
                        }),
                    },
                )),
            },
            response: CreateLoginReceiptCredentialOut::ExplicitError(
                ReceiptCredentialError::PaymentRequired {
                    charge_failure: Some(Box::new(ChargeFailure {
                        processor: PaymentProvider::GooglePlayBilling,
                        code: "code".into(),
                        message: "message".into(),
                        outcome_network_status: Some("ons".into()),
                        outcome_reason: Some("or".into()),
                        outcome_type: Some("ot".into()),
                    })),
                },
            ),
        });
        test_cases
    }
}

#[cfg(test)]
mod tests {
    use test_cases::*;

    use super::*;
    use crate::grpc::testutil::run_tests;
    #[test]
    fn test_create_login_receipt_credential() {
        run_tests(
            create_login_receipt_credential_test_cases(),
            |chat: Unauth<_>,
             CreateLoginReceiptCredentialArgs {
                 payment_processor,
                 purchase_identifier,
                 receipt_credential_request_context,
                 server_params,
                 purchase_time,
                 expected_level,
             }| async move {
                chat.create_login_receipt_credential(
                    payment_processor,
                    purchase_identifier,
                    &receipt_credential_request_context,
                    &server_params,
                    purchase_time,
                    expected_level,
                )
                .await
            },
            |out, result| match out {
                CreateLoginReceiptCredentialOut::Success(receipt) => {
                    assert_eq!(
                        zkgroup::serialize(&result.expect("success")),
                        zkgroup::serialize(&receipt)
                    );
                }
                // assert_matches!() would require that ReceiptCredential impl Debug
                CreateLoginReceiptCredentialOut::UnexpectedError { contains } => assert!(
                    matches!(&result, Err(RequestError::Unexpected { log_safe }) if log_safe.contains(&contains)),
                    "Got {:?}. Expected the unexpected with: {contains:?}",
                    result.err()
                ),
                CreateLoginReceiptCredentialOut::ExplicitError(explicit_error) => {
                    assert!(matches!(result, Err(RequestError::Other(e)) if e == explicit_error))
                }
            },
        );
    }
}
