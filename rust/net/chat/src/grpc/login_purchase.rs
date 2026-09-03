//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use libsignal_net_grpc::proto::chat::errors::{FailedPrecondition, NotFound};
use libsignal_net_grpc::proto::chat::login_purchase::create_login_receipt_credential_response::Response as CreateLoginReceiptCredentialResponseEnum;
use libsignal_net_grpc::proto::chat::login_purchase::login_purchase_client::LoginPurchaseClient;
use libsignal_net_grpc::proto::chat::login_purchase::{
    ChargeFailure as GrpcChargeFailure, CreateLoginReceiptCredentialRequest,
    PaymentProvider as GrpcPaymentProvider,
};
use libsignal_protocol::Timestamp;
use zkgroup::receipts::{
    ReceiptCredential, ReceiptCredentialRequestContext, ReceiptCredentialResponse,
};
use zkgroup::{ReceiptLevel, SECONDS_PER_DAY, ServerPublicParams, ZkGroupVerificationFailure};

use crate::api::{RequestError, Unauth};
use crate::grpc::{GrpcServiceProvider, log_and_send};
use crate::logging::Redact;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentProvider {
    GooglePlayBilling,
    AppleAppStore,
    Stripe,
    Braintree,
}

/// Information about a charge failure.
///
/// Meaningfully interpreting chargeFailure response fields requires inspecting the processor field
/// first.
///
/// For Stripe, code will be one of the [codes defined here](https://stripe.com/docs/api/charges/object#charge_object-failure_code),
/// while message [may contain a further textual description](https://stripe.com/docs/api/charges/object#charge_object-failure_message).
/// The outcome fields are optional, but present values will directly map to Stripe
/// [response properties](https://stripe.com/docs/api/charges/object#charge_object-outcome-network_status)
///
/// For Braintree, the outcome fields will be null. The code and message will contain one of
///   - a processor decline code (as a string) in code, and associated text in message, as defined
///     this [table](https://developer.paypal.com/braintree/docs/reference/general/processor-responses/authorization-responses)
///   - `gateway` in code, with a [reason](https://developer.paypal.com/braintree/articles/control-panel/transactions/gateway-rejections) in message
///   - `code` = "unknown", message = "unknown"
///
/// IAP payment processors will never include charge failure information, and detailed order
/// information should be retrieved from the payment processor directly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChargeFailure {
    pub processor: PaymentProvider,
    /// See [Stripe failure codes](https://stripe.com/docs/api/charges/object#charge_object-failure_code)
    /// or [Braintree decline codes](https://developer.paypal.com/braintree/docs/reference/general/processor-responses/authorization-responses#decline-codes)
    /// depending on which processor was used
    pub code: String,
    /// See [Stripe failure codes](https://stripe.com/docs/api/charges/object#charge_object-failure_code)
    /// or [Braintree decline codes](https://developer.paypal.com/braintree/docs/reference/general/processor-responses/authorization-responses#decline-codes)
    /// depending on which processor was used
    pub message: String,
    /// See [Outcome Network Status](https://stripe.com/docs/api/charges/object#charge_object-outcome-network_status)
    pub outcome_network_status: Option<String>,
    /// See [Outcome Reason](https://stripe.com/docs/api/charges/object#charge_object-outcome-reason)
    pub outcome_reason: Option<String>,
    /// See [Outcome Type](https://stripe.com/docs/api/charges/object#charge_object-outcome-type)
    pub outcome_type: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, displaydoc::Display)]
pub enum ReceiptCredentialError {
    /// The purchase is still pending with the payment provider. The client may retry later.
    PaymentStillProcessing,
    /// The purchase did not complete successfully.
    PaymentRequired {
        charge_failure: Option<Box<ChargeFailure>>,
    },
    /// The payment provider has no purchase with the provided purchase_identifier
    PaymentNotFound,
    /// The purchase was already redeemed for a receipt credential, but with a different receipt
    /// credential request
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

const RECEIPT_LEVEL: ReceiptLevel = 300;
const EXPIRATION_DAYS: u64 = 5 * 366; // ~ 5 years
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
    ) -> Result<ReceiptCredential, RequestError<ReceiptCredentialError>> {
        let mut client = LoginPurchaseClient::new(self.0.service());
        let request = CreateLoginReceiptCredentialRequest {
            processor: match payment_processor {
                PaymentProvider::GooglePlayBilling => GrpcPaymentProvider::GooglePlayBilling.into(),
                PaymentProvider::AppleAppStore => GrpcPaymentProvider::AppleAppStore.into(),
                PaymentProvider::Stripe => GrpcPaymentProvider::Stripe.into(),
                PaymentProvider::Braintree => GrpcPaymentProvider::Braintree.into(),
            },
            purchase_identifier,
            receipt_credential_request: zkgroup::serialize(
                &receipt_credential_request_context.get_request(),
            ),
        };
        let desc = Redact(&request).to_string();
        match log_and_send("unauth", &desc, || {
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
                if out.get_receipt_level() != RECEIPT_LEVEL {
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
                    purchase_time_seconds + (EXPIRATION_DAYS * SECONDS_PER_DAY),
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
                        .map(
                            |GrpcChargeFailure {
                                 processor,
                                 code,
                                 message,
                                 outcome_network_status,
                                 outcome_reason,
                                 outcome_type,
                             }| {
                                Ok(Box::new(ChargeFailure {
                                    processor: match GrpcPaymentProvider::try_from(processor) {
                                        Err(_) | Ok(GrpcPaymentProvider::Unknown) => {
                                            return Err(RequestError::Unexpected {
                                                log_safe: "Unknown returned payment provider"
                                                    .into(),
                                            });
                                        }
                                        Ok(GrpcPaymentProvider::Stripe) => PaymentProvider::Stripe,
                                        Ok(GrpcPaymentProvider::Braintree) => {
                                            PaymentProvider::Braintree
                                        }
                                        Ok(GrpcPaymentProvider::GooglePlayBilling) => {
                                            PaymentProvider::GooglePlayBilling
                                        }
                                        Ok(GrpcPaymentProvider::AppleAppStore) => {
                                            PaymentProvider::AppleAppStore
                                        }
                                    },
                                    code,
                                    message,
                                    outcome_network_status,
                                    outcome_reason,
                                    outcome_type,
                                }))
                            },
                        )
                        .transpose()?,
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
    use libsignal_net_grpc::proto::chat::login_purchase::CreateLoginReceiptCredentialResponse;
    use libsignal_net_grpc::proto::chat::login_purchase::create_login_receipt_credential_response::CreateLoginReceiptCredentialResult;
    use zkgroup::{SECONDS_PER_DAY, ServerSecretParams};

    use super::*;
    use crate::grpc::GrpcTestCase;

    fn day_align(x: u64) -> u64 {
        (x / SECONDS_PER_DAY) * SECONDS_PER_DAY
    }

    #[derive(Clone)]
    pub struct CreateLoginReceiptCredentialArgs {
        pub payment_processor: PaymentProvider,
        pub purchase_identifier: String,
        pub receipt_credential_request_context: ReceiptCredentialRequestContext,
        pub server_params: ServerPublicParams,
        pub purchase_time: Timestamp,
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
        let make_request = |payment_processor| CreateLoginReceiptCredentialArgs {
            payment_processor,
            purchase_identifier: purchase_identifier.clone(),
            receipt_credential_request_context: ctx.clone(),
            server_params: server_params.clone(),
            purchase_time,
        };
        let make_grpc_request =
            |grpc_payment_processor: GrpcPaymentProvider| CreateLoginReceiptCredentialRequest {
                processor: grpc_payment_processor.into(),
                purchase_identifier: purchase_identifier.clone(),
                receipt_credential_request: zkgroup::serialize(&ctx.get_request()),
            };
        let gplay_request = make_request(PaymentProvider::GooglePlayBilling);
        let gplay_grpc_request = make_grpc_request(GrpcPaymentProvider::GooglePlayBilling);
        let mut test_cases = Vec::new();
        let purchase_time_seconds = purchase_time.epoch_millis() / 1000;
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
                RECEIPT_LEVEL,
                zkgroup::Timestamp::from_epoch_seconds(day_align(
                    purchase_time_seconds + (EXPIRATION_DAYS - 2) * SECONDS_PER_DAY,
                )),
            );
            test_cases.push(GrpcTestCase {
                name: format!("Success {payment_processor:?}"),
                method: method.into(),
                request: make_request(payment_processor),
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
        // Unexpected Errors
        {
            let receipt_response = issue_receipt(
                RECEIPT_LEVEL + 1,
                zkgroup::Timestamp::from_epoch_seconds(day_align(
                    purchase_time_seconds + (EXPIRATION_DAYS - 2) * SECONDS_PER_DAY,
                )),
            );
            test_cases.push(GrpcTestCase {
                name: "Level gets checked".into(),
                method: method.into(),
                request: make_request(PaymentProvider::GooglePlayBilling),
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
        {
            let receipt_response = issue_receipt(
                RECEIPT_LEVEL,
                zkgroup::Timestamp::from_epoch_seconds(
                    day_align(purchase_time_seconds + (EXPIRATION_DAYS - 2) * SECONDS_PER_DAY) + 1,
                ),
            );
            test_cases.push(GrpcTestCase {
                name: "Misaligned expiration".into(),
                method: method.into(),
                request: make_request(PaymentProvider::GooglePlayBilling),
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
                + (EXPIRATION_DAYS + EXPIRATION_DAYS_LENIENCY + 1) * SECONDS_PER_DAY,
        ] {
            let receipt_response = issue_receipt(
                RECEIPT_LEVEL,
                zkgroup::Timestamp::from_epoch_seconds(expiration),
            );
            test_cases.push(GrpcTestCase {
                name: format!("Out of bounds expiration {expiration:?}"),
                method: method.into(),
                request: make_request(PaymentProvider::GooglePlayBilling),
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
                    libsignal_net_grpc::proto::chat::login_purchase::PaymentRequired {
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
                    libsignal_net_grpc::proto::chat::login_purchase::PaymentRequired {
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
                    libsignal_net_grpc::proto::chat::login_purchase::PaymentRequired {
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
             }| async move {
                chat.create_login_receipt_credential(
                    payment_processor,
                    purchase_identifier,
                    &receipt_credential_request_context,
                    &server_params,
                    purchase_time,
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
