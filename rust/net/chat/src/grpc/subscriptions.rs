//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::convert::Infallible;
use std::time::{Duration, SystemTime};

use libsignal_net_grpc::proto::chat::errors::{FailedPrecondition, NotFound};
use libsignal_net_grpc::proto::chat::purchase::PaymentMethod as GrpcPaymentMethod;
use libsignal_net_grpc::proto::chat::purchase::product_configuration_client::ProductConfigurationClient;
use libsignal_net_grpc::proto::chat::purchase::subscriptions_client::SubscriptionsClient;
use libsignal_net_grpc::proto::chat::purchase::{
    GetConfigurationRequest, GetConfigurationResponse, GetReceiptCredentialRequest,
    get_receipt_credential_response,
};
use zkgroup::receipts::{
    ReceiptCredential, ReceiptCredentialRequestContext, ReceiptCredentialResponse,
};
use zkgroup::{SECONDS_PER_DAY, ServerPublicParams, ZkGroupVerificationFailure};

use super::{GrpcServiceProvider, log_and_send};
use crate::api::purchase::{ChargeFailure, PaymentMethod};
use crate::api::{RequestError, Unauth};
use crate::logging::{Redact, RedactBytesAsHex};

pub type SubscriberId = [u8; 32];
pub type CurrencyAmount = u64;

impl TryFrom<GrpcPaymentMethod> for PaymentMethod {
    type Error = RequestError<Infallible>;

    fn try_from(value: GrpcPaymentMethod) -> Result<Self, Self::Error> {
        match value {
            GrpcPaymentMethod::Unknown => Err(RequestError::Unexpected {
                log_safe: "Unknown payment method".into(),
            }),
            GrpcPaymentMethod::Card => Ok(Self::Card),
            GrpcPaymentMethod::SepaDebit => Ok(Self::SepaDebit),
            GrpcPaymentMethod::Ideal => Ok(Self::Ideal),
            GrpcPaymentMethod::Paypal => Ok(Self::PayPal),
            GrpcPaymentMethod::GooglePlayBilling => Ok(Self::GooglePlayBilling),
            GrpcPaymentMethod::AppleAppStore => Ok(Self::AppleAppStore),
        }
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct PurchaseProductConfiguration {
    // Map of lower-cased ISO 3-letter currency codes to currency-specific configuration
    pub currencies: HashMap<String, CurrencyConfiguration>,
    // Map of numeric donation level IDs to level-specific badge configuration
    pub badge_levels: HashMap<zkgroup::ReceiptLevel, BadgeLevelConfiguration>,
    // Configuration for backup subscription options
    pub backup: BackupConfiguration,
    // Maximum value of a one-time SEPA donation, in EUR [minor units](https://docs.stripe.com/currencies#minor-units)
    pub sepa_maximum_euros: CurrencyAmount,
    // Configuration for one-time Signal Login purchases
    pub login: LoginConfiguration,
}

impl TryFrom<GetConfigurationResponse> for PurchaseProductConfiguration {
    type Error = RequestError<Infallible>;

    fn try_from(value: GetConfigurationResponse) -> Result<Self, Self::Error> {
        let GetConfigurationResponse {
            currencies,
            badge_levels,
            backup,
            sepa_maximum_euros,
            login,
        } = value;
        let currencies = currencies
            .into_iter()
            .map(|(code, info)| Ok((code, info.try_into()?)))
            .collect::<Result<_, RequestError<_>>>()?;
        let badge_levels = badge_levels
            .into_iter()
            .map(|(level, info)| Ok((level, info.try_into()?)))
            .collect::<Result<_, RequestError<_>>>()?;
        let backup = backup
            .ok_or_else(|| RequestError::Unexpected {
                log_safe: "missing backup info".to_owned(),
            })?
            .try_into()?;
        let login = login
            .ok_or_else(|| RequestError::Unexpected {
                log_safe: "missing login info".to_owned(),
            })?
            .try_into()?;

        Ok(PurchaseProductConfiguration {
            currencies,
            badge_levels,
            backup,
            sepa_maximum_euros,
            login,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct CurrencyConfiguration {
    // Minimum one-time donation in the currency's minor unit
    pub minimum: CurrencyAmount,
    // Map of one-time donation level IDs to suggested amounts
    pub one_time_donation_amounts: HashMap<zkgroup::ReceiptLevel, Vec<CurrencyAmount>>,
    // Map of subscription level IDs to the amount charged in the currency's minor
    // unit
    pub subscription_amounts: HashMap<zkgroup::ReceiptLevel, CurrencyAmount>,
    // Map of backup subscription level IDs to the amount charged in the
    // currency's minor unit
    pub backup_subscription_amounts: HashMap<zkgroup::ReceiptLevel, CurrencyAmount>,
    pub supported_payment_methods: Vec<PaymentMethod>,
}

impl TryFrom<libsignal_net_grpc::proto::chat::purchase::CurrencyConfiguration>
    for CurrencyConfiguration
{
    type Error = RequestError<Infallible>;

    fn try_from(
        value: libsignal_net_grpc::proto::chat::purchase::CurrencyConfiguration,
    ) -> Result<Self, Self::Error> {
        let libsignal_net_grpc::proto::chat::purchase::CurrencyConfiguration {
            minimum,
            one_time,
            subscription,
            backup_subscription,
            supported_payment_methods,
        } = value;
        Ok(Self {
            minimum,
            one_time_donation_amounts: one_time
                .into_iter()
                .map(|(level, amounts)| (level, amounts.amounts))
                .collect(),
            subscription_amounts: subscription,
            backup_subscription_amounts: backup_subscription,
            supported_payment_methods: supported_payment_methods
                .into_iter()
                .flat_map(|raw| {
                    PaymentMethod::try_from(GrpcPaymentMethod::try_from(raw).unwrap_or_default())
                        .inspect_err(|_| log::warn!("ignoring unknown payment method: {raw}"))
                        .ok()
                })
                .collect(),
        })
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct BadgeLevelConfiguration {
    // The ID of the badge awarded at this level. Resolve to full badge details
    // via RemoteConfiguration.GetBadges.
    pub badge_id: String,

    // The duration for which a badge is valid. Present only for
    // one-time (boost, gift) badges
    pub badge_duration: Option<Duration>,
}

impl TryFrom<libsignal_net_grpc::proto::chat::purchase::LevelConfiguration>
    for BadgeLevelConfiguration
{
    type Error = RequestError<Infallible>;

    fn try_from(
        value: libsignal_net_grpc::proto::chat::purchase::LevelConfiguration,
    ) -> Result<Self, Self::Error> {
        let libsignal_net_grpc::proto::chat::purchase::LevelConfiguration {
            badge_id,
            badge_duration_seconds,
        } = value;
        Ok(Self {
            badge_id,
            badge_duration: badge_duration_seconds
                .map(|secs| {
                    if secs == 0 {
                        Err(RequestError::Unexpected {
                            log_safe: "badge_duration_seconds was present but 0".into(),
                        })
                    } else {
                        Ok(Duration::from_secs(secs.into()))
                    }
                })
                .transpose()?,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct BackupConfiguration {
    // A map of numeric backup level IDs to level-specific backup configuration
    pub levels: HashMap<zkgroup::ReceiptLevel, BackupLevelConfiguration>,
    // The number of days of media a free tier backup user gets
    pub free_tier_media_days: u32,
}

impl TryFrom<libsignal_net_grpc::proto::chat::purchase::BackupConfiguration>
    for BackupConfiguration
{
    type Error = RequestError<Infallible>;

    fn try_from(
        value: libsignal_net_grpc::proto::chat::purchase::BackupConfiguration,
    ) -> Result<Self, Self::Error> {
        let libsignal_net_grpc::proto::chat::purchase::BackupConfiguration {
            levels,
            free_tier_media_days,
        } = value;
        let levels = levels
            .into_iter()
            .map(|(level, info)| Ok((level, info.try_into()?)))
            .collect::<Result<_, RequestError<_>>>()?;
        Ok(Self {
            levels,
            free_tier_media_days,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct BackupLevelConfiguration {
    // The amount of media storage in bytes that a paying subscriber may store
    pub storage_allowance_bytes: u64,
    // The play billing productID associated with this backup level
    pub play_product_id: String,
    // The duration, in days, for which your backed up media is retained on the server after you stop refreshing with a paid credential
    pub media_ttl_days: u32,
}

impl TryFrom<libsignal_net_grpc::proto::chat::purchase::BackupLevelConfiguration>
    for BackupLevelConfiguration
{
    type Error = RequestError<Infallible>;

    fn try_from(
        value: libsignal_net_grpc::proto::chat::purchase::BackupLevelConfiguration,
    ) -> Result<Self, Self::Error> {
        let libsignal_net_grpc::proto::chat::purchase::BackupLevelConfiguration {
            storage_allowance_bytes,
            play_product_id,
            media_ttl_days,
        } = value;
        Ok(Self {
            storage_allowance_bytes,
            play_product_id,
            media_ttl_days,
        })
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct LoginConfiguration {
    // The receipt level associated with a Signal Login purchase
    pub level: zkgroup::ReceiptLevel,
    // The play billing productID associated with a Signal Login purchase
    pub play_product_id: String,
    // The play billing optionID to use to purchase a Signal Login
    pub play_option_id: String,
    // The App Store productID associated with a Signal Login purchase
    pub app_store_product_id: String,
}

impl TryFrom<libsignal_net_grpc::proto::chat::purchase::LoginConfiguration> for LoginConfiguration {
    type Error = RequestError<Infallible>;

    fn try_from(
        value: libsignal_net_grpc::proto::chat::purchase::LoginConfiguration,
    ) -> Result<Self, Self::Error> {
        let libsignal_net_grpc::proto::chat::purchase::LoginConfiguration {
            level,
            play_product_id,
            play_option_id,
            app_store_product_id,
        } = value;
        Ok(Self {
            level,
            play_product_id,
            play_option_id,
            app_store_product_id,
        })
    }
}

#[derive(Clone, Debug, displaydoc::Display)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum ReceiptCredentialError {
    /// No invoice has been issued for this subscription OR invoice is in 'draft' or 'open' state.
    NoPaidInvoice,
    /// The purchase did not complete successfully.
    PaymentRequired {
        charge_failure: Option<Box<ChargeFailure>>,
    },
    /// The subscriber did not exist or it did not have an associated subscription.
    SubscriberNotFound,
    /// The purchase was already redeemed for a receipt credential using a different request.
    ReceiptAlreadyIssued,
}

const UNEXPECTED_CANT_RECV: &str = "Failed to receive receipt credential response";
const UNEXPECTED_EXPIRATION_OUT_OF_RANGE: &str =
    "Invalid receipt: expiration time outside of range";

impl<T: GrpcServiceProvider> Unauth<T> {
    pub async fn get_purchase_product_configuration(
        &self,
    ) -> Result<PurchaseProductConfiguration, RequestError<Infallible>> {
        let mut client = ProductConfigurationClient::new(self.0.service());
        let request = GetConfigurationRequest {};
        let desc = Redact(&request).to_string();
        log_and_send(Self::LOG_TAG, &desc, || client.get_configuration(request))
            .await?
            .into_inner()
            .try_into()
    }

    pub async fn get_subscription_receipt_credential(
        &self,
        subscriber_id: SubscriberId,
        receipt_credential_request_context: &ReceiptCredentialRequestContext,
        server_params: &ServerPublicParams,
    ) -> Result<ReceiptCredential, RequestError<ReceiptCredentialError>> {
        let mut client = SubscriptionsClient::new(self.0.service());
        let request = GetReceiptCredentialRequest {
            subscriber_id: subscriber_id.to_vec(),
            receipt_credential_request: zkgroup::serialize(
                &receipt_credential_request_context.get_request(),
            ),
        };
        let desc = Redact(&request).to_string();
        match log_and_send(Self::LOG_TAG, &desc, || {
            client.get_receipt_credential(request)
        })
        .await?
        .into_inner()
        .response
        .ok_or_else(|| RequestError::Unexpected {
            log_safe: "Missing response".to_string(),
        })? {
            get_receipt_credential_response::Response::Success(
                get_receipt_credential_response::GetReceiptCredentialResult {
                    receipt_credential_response,
                },
            ) => {
                let response: ReceiptCredentialResponse =
                    zkgroup::deserialize(&receipt_credential_response).map_err(|_| {
                        RequestError::Unexpected {
                            log_safe: "Can't deserialize receipt credential response".into(),
                        }
                    })?;
                let out = server_params
                    .receive_receipt_credential(receipt_credential_request_context, &response)
                    .map_err(|ZkGroupVerificationFailure| RequestError::Unexpected {
                        log_safe: UNEXPECTED_CANT_RECV.into(),
                    })?;
                if !out
                    .get_receipt_expiration_time()
                    .epoch_seconds()
                    .is_multiple_of(SECONDS_PER_DAY)
                {
                    return Err(RequestError::Unexpected {
                        log_safe: "Invalid receipt: expiration time".into(),
                    });
                }
                // Check the expiration:
                // - must not be more than 24 hours ago
                // - must not be more than 90 days in the future
                let yesterday_at_this_time =
                    SystemTime::now() - Duration::from_secs(SECONDS_PER_DAY);
                let expiration_time = SystemTime::UNIX_EPOCH
                    + Duration::from_secs(out.get_receipt_expiration_time().epoch_seconds());
                if !expiration_time
                    .duration_since(yesterday_at_this_time)
                    .is_ok_and(|duration| duration < Duration::from_secs(91 * SECONDS_PER_DAY))
                {
                    return Err(RequestError::Unexpected {
                        log_safe: UNEXPECTED_EXPIRATION_OUT_OF_RANGE.into(),
                    });
                }
                Ok(out)
            }
            get_receipt_credential_response::Response::SubscriberNotFound(NotFound {}) => Err(
                RequestError::Other(ReceiptCredentialError::SubscriberNotFound),
            ),
            get_receipt_credential_response::Response::NoPaidInvoice(FailedPrecondition {
                description,
            }) => {
                log::warn!("NoPaidInvoice: {description}");
                Err(RequestError::Other(ReceiptCredentialError::NoPaidInvoice))
            }
            get_receipt_credential_response::Response::PaymentRequired(payment_required) => Err(
                RequestError::Other(ReceiptCredentialError::PaymentRequired {
                    charge_failure: payment_required
                        .charge_failure
                        .map(|charge_failure| Ok(Box::new(charge_failure.try_into()?)))
                        .transpose()
                        .map_err(RequestError::with_other)?,
                }),
            ),
            get_receipt_credential_response::Response::AlreadyRedeemed(FailedPrecondition {
                description,
            }) => {
                log::warn!("AlreadyRedeemed {description}");
                Err(RequestError::Other(
                    ReceiptCredentialError::ReceiptAlreadyIssued,
                ))
            }
        }
    }
}

impl std::fmt::Display for Redact<GetReceiptCredentialRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let GetReceiptCredentialRequest {
            subscriber_id,
            receipt_credential_request,
        } = &self.0;
        f.debug_struct("GetReceiptCredentialRequest")
            .field("subscriber_id", &RedactBytesAsHex(subscriber_id))
            .field(
                "receipt_credential_request.len()",
                &receipt_credential_request.len(),
            )
            .finish()
    }
}

impl std::fmt::Display for Redact<GetConfigurationRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let GetConfigurationRequest {} = &self.0;
        f.debug_struct("GetConfigurationRequest").finish()
    }
}

pub mod test_cases {
    use libsignal_net_grpc::proto::chat::errors::{FailedPrecondition, NotFound};
    use libsignal_net_grpc::proto::chat::purchase::get_receipt_credential_response::GetReceiptCredentialResult;
    use libsignal_net_grpc::proto::chat::purchase::{
        AmountList, BackupConfiguration as GrpcBackupConfiguration,
        BackupLevelConfiguration as GrpcBackupLevelConfiguration,
        ChargeFailure as GrpcChargeFailure, CurrencyConfiguration as GrpcCurrencyConfiguration,
        GetReceiptCredentialResponse, LevelConfiguration as GrpcLevelConfiguration,
        LoginConfiguration as GrpcLoginConfiguration, PaymentProvider as GrpcPaymentProvider,
    };
    use zkgroup::ServerSecretParams;

    use super::*;
    use crate::api::purchase::PaymentProvider;
    use crate::grpc::GrpcTestCase;

    pub(crate) fn valid_get_configuration_response() -> GetConfigurationResponse {
        GetConfigurationResponse {
            currencies: HashMap::from_iter([
                (
                    "XTS".to_owned(),
                    GrpcCurrencyConfiguration {
                        minimum: 100,
                        one_time: HashMap::from_iter([(
                            2,
                            AmountList {
                                amounts: vec![100, 200, 300],
                            },
                        )]),
                        subscription: HashMap::from_iter([(10, 1000), (20, 2000), (30, 3000)]),
                        backup_subscription: HashMap::from_iter([(100, 399)]),
                        supported_payment_methods: vec![
                            GrpcPaymentMethod::Card.into(),
                            GrpcPaymentMethod::Paypal.into(),
                            GrpcPaymentMethod::SepaDebit.into(),
                            GrpcPaymentMethod::Ideal.into(),
                        ],
                    },
                ),
                (
                    "USD".to_owned(),
                    GrpcCurrencyConfiguration {
                        minimum: 200,
                        one_time: HashMap::from_iter([(
                            2,
                            AmountList {
                                amounts: vec![500, 1000, 2000],
                            },
                        )]),
                        subscription: HashMap::from_iter([(10, 500), (20, 1000), (30, 2000)]),
                        backup_subscription: HashMap::from_iter([(100, 199)]),
                        supported_payment_methods: vec![
                            GrpcPaymentMethod::AppleAppStore.into(),
                            GrpcPaymentMethod::GooglePlayBilling.into(),
                        ],
                    },
                ),
            ]),
            badge_levels: HashMap::from_iter([
                (
                    2,
                    GrpcLevelConfiguration {
                        badge_id: "sprout".into(),
                        badge_duration_seconds: Some(
                            30 * u32::try_from(SECONDS_PER_DAY).expect("fits in u32"),
                        ),
                    },
                ),
                (
                    10,
                    GrpcLevelConfiguration {
                        badge_id: "star".into(),
                        badge_duration_seconds: None,
                    },
                ),
                (
                    20,
                    GrpcLevelConfiguration {
                        badge_id: "planet".into(),
                        badge_duration_seconds: None,
                    },
                ),
                (
                    30,
                    GrpcLevelConfiguration {
                        badge_id: "sun".into(),
                        badge_duration_seconds: None,
                    },
                ),
            ]),
            backup: Some(GrpcBackupConfiguration {
                levels: HashMap::from_iter([(
                    -2i64 as u64,
                    GrpcBackupLevelConfiguration {
                        storage_allowance_bytes: 9 * 1024 * 1024 * 1024,
                        play_product_id: "backups-media-tier".into(),
                        media_ttl_days: 90,
                    },
                )]),
                free_tier_media_days: 45,
            }),
            sepa_maximum_euros: 9000,
            login: Some(GrpcLoginConfiguration {
                level: -4i64 as u64,
                play_product_id: "signal-login".into(),
                play_option_id: "signal-login-option".into(),
                app_store_product_id: "SignalLogin".into(),
            }),
        }
    }

    pub fn get_product_configuration_test_cases() -> Vec<
        GrpcTestCase<
            (),
            GetConfigurationRequest,
            GetConfigurationResponse,
            PurchaseProductConfiguration,
        >,
    > {
        // We'll test the individual layers of conversion separately and just return one maximal
        // configuration here.
        vec![GrpcTestCase {
            name: "success".to_owned(),
            method: "/org.signal.chat.purchase.ProductConfiguration/GetConfiguration".to_owned(),
            request: (),
            request_grpc: GetConfigurationRequest {},
            response_grpc: valid_get_configuration_response(),
            response: PurchaseProductConfiguration {
                currencies: HashMap::from_iter([
                    (
                        "XTS".to_owned(),
                        CurrencyConfiguration {
                            minimum: 100,
                            one_time_donation_amounts: HashMap::from_iter([(
                                2,
                                vec![100, 200, 300],
                            )]),
                            subscription_amounts: HashMap::from_iter([
                                (10, 1000),
                                (20, 2000),
                                (30, 3000),
                            ]),
                            backup_subscription_amounts: HashMap::from_iter([(100, 399)]),
                            supported_payment_methods: vec![
                                PaymentMethod::Card,
                                PaymentMethod::PayPal,
                                PaymentMethod::SepaDebit,
                                PaymentMethod::Ideal,
                            ],
                        },
                    ),
                    (
                        "USD".to_owned(),
                        CurrencyConfiguration {
                            minimum: 200,
                            one_time_donation_amounts: HashMap::from_iter([(
                                2,
                                vec![500, 1000, 2000],
                            )]),
                            subscription_amounts: HashMap::from_iter([
                                (10, 500),
                                (20, 1000),
                                (30, 2000),
                            ]),
                            backup_subscription_amounts: HashMap::from_iter([(100, 199)]),
                            supported_payment_methods: vec![
                                PaymentMethod::AppleAppStore,
                                PaymentMethod::GooglePlayBilling,
                            ],
                        },
                    ),
                ]),
                badge_levels: HashMap::from_iter([
                    (
                        2,
                        BadgeLevelConfiguration {
                            badge_id: "sprout".into(),
                            badge_duration: Some(Duration::from_secs(30 * SECONDS_PER_DAY)),
                        },
                    ),
                    (
                        10,
                        BadgeLevelConfiguration {
                            badge_id: "star".into(),
                            badge_duration: None,
                        },
                    ),
                    (
                        20,
                        BadgeLevelConfiguration {
                            badge_id: "planet".into(),
                            badge_duration: None,
                        },
                    ),
                    (
                        30,
                        BadgeLevelConfiguration {
                            badge_id: "sun".into(),
                            badge_duration: None,
                        },
                    ),
                ]),
                backup: BackupConfiguration {
                    levels: HashMap::from_iter([(
                        -2i64 as u64,
                        BackupLevelConfiguration {
                            storage_allowance_bytes: 9 * 1024 * 1024 * 1024,
                            play_product_id: "backups-media-tier".into(),
                            media_ttl_days: 90,
                        },
                    )]),
                    free_tier_media_days: 45,
                },
                sepa_maximum_euros: 9000,
                login: LoginConfiguration {
                    level: -4i64 as u64,
                    play_product_id: "signal-login".into(),
                    play_option_id: "signal-login-option".into(),
                    app_store_product_id: "SignalLogin".into(),
                },
            },
        }]
    }

    fn day_align(x: u64) -> u64 {
        (x / SECONDS_PER_DAY) * SECONDS_PER_DAY
    }

    #[derive(Clone)]
    pub struct GetReceiptCredentialArgs {
        pub subscriber_id: SubscriberId,
        pub receipt_credential_request_context: ReceiptCredentialRequestContext,
        pub server_params: ServerPublicParams,
    }
    #[allow(clippy::large_enum_variant)]
    pub enum GetReceiptCredentialOut {
        Success(ReceiptCredential),
        UnexpectedError { contains: String },
        ExplicitError(ReceiptCredentialError),
    }
    pub fn get_receipt_credential_test_cases() -> Vec<
        GrpcTestCase<
            GetReceiptCredentialArgs,
            GetReceiptCredentialRequest,
            GetReceiptCredentialResponse,
            GetReceiptCredentialOut,
        >,
    > {
        let server_secret_params = ServerSecretParams::generate([0x01; _]);
        let server_params = server_secret_params.get_public_params();
        let ctx = server_params.create_receipt_credential_request_context([0x02; _], [0x04; _]);
        let method = "/org.signal.chat.purchase.Subscriptions/GetReceiptCredential";
        let subscriber_id = [b's'; 32];
        let issue_receipt = |level, expiration| {
            server_secret_params.issue_receipt_credential(
                [0x5; _],
                &ctx.get_request(),
                expiration,
                level,
            )
        };
        let request = GetReceiptCredentialArgs {
            subscriber_id,
            receipt_credential_request_context: ctx.clone(),
            server_params: server_params.clone(),
        };
        let grpc_request = GetReceiptCredentialRequest {
            subscriber_id: subscriber_id.into(),
            receipt_credential_request: zkgroup::serialize(&ctx.get_request()),
        };
        let now_seconds = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("present day")
            .as_secs();
        let valid_response = issue_receipt(
            200,
            zkgroup::Timestamp::from_epoch_seconds(day_align(now_seconds + 3 * SECONDS_PER_DAY)),
        );
        let just_barely_expired_response = issue_receipt(
            200,
            zkgroup::Timestamp::from_epoch_seconds(day_align(now_seconds)),
        );
        let mut test_cases = vec![
            GrpcTestCase {
                name: "Success".into(),
                method: method.into(),
                request: request.clone(),
                request_grpc: grpc_request.clone(),
                response_grpc: GetReceiptCredentialResponse {
                    response: Some(get_receipt_credential_response::Response::Success(
                        GetReceiptCredentialResult {
                            receipt_credential_response: zkgroup::serialize(&valid_response),
                        },
                    )),
                },
                response: GetReceiptCredentialOut::Success(
                    server_params
                        .receive_receipt_credential(&ctx, &valid_response)
                        .expect("can receive"),
                ),
            },
            GrpcTestCase {
                name: "Misaligned expiration".into(),
                method: method.into(),
                request: request.clone(),
                request_grpc: grpc_request.clone(),
                response_grpc: GetReceiptCredentialResponse {
                    response: Some(get_receipt_credential_response::Response::Success(
                        GetReceiptCredentialResult {
                            receipt_credential_response: zkgroup::serialize(&issue_receipt(
                                200,
                                zkgroup::Timestamp::from_epoch_seconds(
                                    day_align(now_seconds + 3 * SECONDS_PER_DAY) + 1,
                                ),
                            )),
                        },
                    )),
                },
                response: GetReceiptCredentialOut::UnexpectedError {
                    contains: UNEXPECTED_CANT_RECV.into(),
                },
            },
            GrpcTestCase {
                name: "Already expired".into(),
                method: method.into(),
                request: request.clone(),
                request_grpc: grpc_request.clone(),
                response_grpc: GetReceiptCredentialResponse {
                    response: Some(get_receipt_credential_response::Response::Success(
                        GetReceiptCredentialResult {
                            receipt_credential_response: zkgroup::serialize(&issue_receipt(
                                200,
                                zkgroup::Timestamp::from_epoch_seconds(day_align(
                                    now_seconds - 3 * SECONDS_PER_DAY,
                                )),
                            )),
                        },
                    )),
                },
                response: GetReceiptCredentialOut::UnexpectedError {
                    contains: UNEXPECTED_EXPIRATION_OUT_OF_RANGE.into(),
                },
            },
            GrpcTestCase {
                name: "Expires too far in the future".into(),
                method: method.into(),
                request: request.clone(),
                request_grpc: grpc_request.clone(),
                response_grpc: GetReceiptCredentialResponse {
                    response: Some(get_receipt_credential_response::Response::Success(
                        GetReceiptCredentialResult {
                            receipt_credential_response: zkgroup::serialize(&issue_receipt(
                                200,
                                zkgroup::Timestamp::from_epoch_seconds(day_align(
                                    now_seconds + 91 * SECONDS_PER_DAY,
                                )),
                            )),
                        },
                    )),
                },
                response: GetReceiptCredentialOut::UnexpectedError {
                    contains: UNEXPECTED_EXPIRATION_OUT_OF_RANGE.into(),
                },
            },
            GrpcTestCase {
                name: "Just barely expired but still accepted".into(),
                method: method.into(),
                request: request.clone(),
                request_grpc: grpc_request.clone(),
                response_grpc: GetReceiptCredentialResponse {
                    response: Some(get_receipt_credential_response::Response::Success(
                        GetReceiptCredentialResult {
                            receipt_credential_response: zkgroup::serialize(
                                &just_barely_expired_response,
                            ),
                        },
                    )),
                },
                response: GetReceiptCredentialOut::Success(
                    server_params
                        .receive_receipt_credential(&ctx, &just_barely_expired_response)
                        .expect("can receive"),
                ),
            },
        ];
        // Simple Error cases
        for (nice_error, grpc_error) in [
            (
                ReceiptCredentialError::NoPaidInvoice,
                get_receipt_credential_response::Response::NoPaidInvoice(FailedPrecondition {
                    description: "error".into(),
                }),
            ),
            (
                ReceiptCredentialError::SubscriberNotFound,
                get_receipt_credential_response::Response::SubscriberNotFound(NotFound {}),
            ),
            (
                ReceiptCredentialError::ReceiptAlreadyIssued,
                get_receipt_credential_response::Response::AlreadyRedeemed(FailedPrecondition {
                    description: "error".into(),
                }),
            ),
        ] {
            test_cases.push(GrpcTestCase {
                name: format!("Error {nice_error:?}"),
                method: method.to_string(),
                request: request.clone(),
                request_grpc: grpc_request.clone(),
                response_grpc: GetReceiptCredentialResponse {
                    response: Some(grpc_error),
                },
                response: GetReceiptCredentialOut::ExplicitError(nice_error),
            });
        }
        // Payment Required error cases
        test_cases.push(GrpcTestCase {
            name: "Payment Required: None".into(),
            method: method.to_string(),
            request: request.clone(),
            request_grpc: grpc_request.clone(),
            response_grpc: GetReceiptCredentialResponse {
                response: Some(get_receipt_credential_response::Response::PaymentRequired(
                    libsignal_net_grpc::proto::chat::purchase::PaymentRequired {
                        charge_failure: None,
                    },
                )),
            },
            response: GetReceiptCredentialOut::ExplicitError(
                ReceiptCredentialError::PaymentRequired {
                    charge_failure: None,
                },
            ),
        });
        test_cases.push(GrpcTestCase {
            name: "Payment Required: None fields".into(),
            method: method.to_string(),
            request: request.clone(),
            request_grpc: grpc_request.clone(),
            response_grpc: GetReceiptCredentialResponse {
                response: Some(get_receipt_credential_response::Response::PaymentRequired(
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
            response: GetReceiptCredentialOut::ExplicitError(
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
            request: request.clone(),
            request_grpc: grpc_request.clone(),
            response_grpc: GetReceiptCredentialResponse {
                response: Some(get_receipt_credential_response::Response::PaymentRequired(
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
            response: GetReceiptCredentialOut::ExplicitError(
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
    use std::fmt::Debug;

    use assert_matches::assert_matches;
    use libsignal_net_grpc::proto::chat::purchase::{
        CurrencyConfiguration as GrpcCurrencyConfiguration,
        LevelConfiguration as GrpcBadgeLevelConfiguration,
    };

    use super::test_cases::*;
    use super::*;
    use crate::grpc::testutil::run_tests;

    #[test]
    fn test_get_product_configuration() {
        run_tests(
            get_product_configuration_test_cases(),
            |chat: Unauth<_>, ()| async move { chat.get_purchase_product_configuration().await },
            |out, result| {
                pretty_assertions::assert_eq!(out, result.expect("success"));
            },
        );
    }

    #[test]
    fn test_get_product_configuration_malformed_cases() {
        #[track_caller]
        fn assert_err<T: Debug>(name: &str, input: Result<T, RequestError<Infallible>>) {
            assert_matches!(
                input.expect_err("should have failed"),
                RequestError::Unexpected { log_safe: _ },
                "{name}"
            );
        }

        // First, check the basic success case.
        _ = PurchaseProductConfiguration::try_from(valid_get_configuration_response())
            .expect("valid");

        // Failures at the top level.
        assert_err(
            "missing backup",
            PurchaseProductConfiguration::try_from(GetConfigurationResponse {
                backup: None,
                ..valid_get_configuration_response()
            }),
        );
        assert_err(
            "missing login",
            PurchaseProductConfiguration::try_from(GetConfigurationResponse {
                login: None,
                ..valid_get_configuration_response()
            }),
        );

        // Bad payment methods - not an error!
        assert_eq!(
            CurrencyConfiguration::try_from(GrpcCurrencyConfiguration {
                supported_payment_methods: vec![
                    GrpcPaymentMethod::Card.into(),
                    GrpcPaymentMethod::Unknown.into(),
                    999,
                    GrpcPaymentMethod::SepaDebit.into(),
                ],
                ..Default::default()
            })
            .expect("success")
            .supported_payment_methods,
            vec![PaymentMethod::Card, PaymentMethod::SepaDebit],
            "should ignore unrecognized payment methods"
        );

        // Bad badge duration
        assert_err(
            "badge_duration_seconds == 0",
            BadgeLevelConfiguration::try_from(GrpcBadgeLevelConfiguration {
                badge_id: "badge".to_owned(),
                badge_duration_seconds: Some(0),
            }),
        );
    }

    #[test]
    fn test_get_receipt_credential() {
        run_tests(
            get_receipt_credential_test_cases(),
            |chat: Unauth<_>,
             GetReceiptCredentialArgs {
                 subscriber_id,
                 receipt_credential_request_context,
                 server_params,
             }| async move {
                chat.get_subscription_receipt_credential(
                    subscriber_id,
                    &receipt_credential_request_context,
                    &server_params,
                )
                .await
            },
            |out, result| match out {
                GetReceiptCredentialOut::Success(receipt) => {
                    assert_eq!(
                        zkgroup::serialize(&result.expect("success")),
                        zkgroup::serialize(&receipt)
                    );
                }
                // assert_matches!() would require that ReceiptCredential impl Debug
                GetReceiptCredentialOut::UnexpectedError { contains } => assert!(
                    matches!(&result, Err(RequestError::Unexpected { log_safe }) if log_safe.contains(&contains)),
                    "Got {:?}. Expected the unexpected with: {contains:?}",
                    result.err()
                ),
                GetReceiptCredentialOut::ExplicitError(explicit_error) => {
                    assert!(matches!(result, Err(RequestError::Other(e)) if e == explicit_error))
                }
            },
        );
    }
}
