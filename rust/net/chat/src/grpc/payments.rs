//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::collections::HashMap;
use std::convert::Infallible;

use libsignal_net_grpc::proto::chat::payments::get_currency_conversions_response::CurrencyConversionEntity;
use libsignal_net_grpc::proto::chat::payments::payments_client::PaymentsClient;
use libsignal_net_grpc::proto::chat::payments::{
    GetCurrencyConversionsRequest, GetCurrencyConversionsResponse,
};
use libsignal_protocol::Timestamp;

use crate::api::{Auth, RequestError};
use crate::grpc::{GrpcServiceProvider, log_and_send};
use crate::logging::Redact;

impl std::fmt::Display for Redact<GetCurrencyConversionsRequest> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GetCurrencyConversionsRequest").finish()
    }
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct Currency {
    pub base: String,
    /// The values of this map are decimal conversion rates.
    pub conversions: HashMap<String, String>,
}

#[derive(Clone)]
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub struct CurrencyConversions {
    pub timestamp_ms: Timestamp,
    pub currencies: Vec<Currency>,
}

impl<T: GrpcServiceProvider> Auth<T> {
    /// Return the current currency conversion rates.
    pub async fn get_currency_conversions(
        &self,
    ) -> Result<CurrencyConversions, RequestError<Infallible>> {
        let mut client = PaymentsClient::new(self.0.service());
        let request = GetCurrencyConversionsRequest {};
        let desc = Redact(&request).to_string();
        let GetCurrencyConversionsResponse {
            timestamp,
            currencies,
        } = log_and_send("auth", &desc, || client.get_currency_conversions(request))
            .await?
            .into_inner();
        Ok(CurrencyConversions {
            timestamp_ms: Timestamp::from_epoch_millis(timestamp),
            currencies: currencies
                .into_iter()
                .map(|CurrencyConversionEntity { base, conversions }| Currency {
                    base,
                    conversions,
                })
                .collect(),
        })
    }
}

pub mod test_cases {
    use super::*;
    use crate::grpc::GrpcTestCase;
    pub type GetCurrencyConversionsArgs = ();
    pub type GetCurrencyConversionsOut = CurrencyConversions;
    pub fn get_currency_conversions_test_cases() -> Vec<
        GrpcTestCase<
            GetCurrencyConversionsArgs,
            GetCurrencyConversionsRequest,
            GetCurrencyConversionsResponse,
            GetCurrencyConversionsOut,
        >,
    > {
        let method = "/org.signal.chat.payments.Payments/GetCurrencyConversions";
        let timestamp = 1782835609203;
        vec![GrpcTestCase {
            name: "test case".to_string(),
            method: method.to_string(),
            request: (),
            request_grpc: GetCurrencyConversionsRequest {},
            response_grpc: GetCurrencyConversionsResponse {
                timestamp,
                currencies: vec![
                    CurrencyConversionEntity {
                        base: "base1".to_string(),
                        conversions: HashMap::from_iter([
                            ("base1.one".to_string(), "base1.one_value".to_string()),
                            ("base1.two".to_string(), "base1.two_value".to_string()),
                        ]),
                    },
                    CurrencyConversionEntity {
                        base: "base2".to_string(),
                        conversions: HashMap::from_iter([
                            ("base2.one".to_string(), "base2.one_value".to_string()),
                            ("base2.two".to_string(), "base2.two_value".to_string()),
                        ]),
                    },
                ],
            },
            response: CurrencyConversions {
                timestamp_ms: Timestamp::from_epoch_millis(timestamp),
                currencies: vec![
                    Currency {
                        base: "base1".to_string(),
                        conversions: HashMap::from_iter([
                            ("base1.one".to_string(), "base1.one_value".to_string()),
                            ("base1.two".to_string(), "base1.two_value".to_string()),
                        ]),
                    },
                    Currency {
                        base: "base2".to_string(),
                        conversions: HashMap::from_iter([
                            ("base2.one".to_string(), "base2.one_value".to_string()),
                            ("base2.two".to_string(), "base2.two_value".to_string()),
                        ]),
                    },
                ],
            },
        }]
    }
}

#[test]
fn test_get_currency_conversions() {
    use test_cases::*;
    crate::grpc::testutil::run_tests(
        get_currency_conversions_test_cases(),
        |chat: Auth<_>, ()| async move { chat.get_currency_conversions().await },
        |resp, result| assert_eq!(resp, result.expect("Success")),
    );
}
