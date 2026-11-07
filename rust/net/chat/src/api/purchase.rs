//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentProvider {
    GooglePlayBilling,
    AppleAppStore,
    Stripe,
    Braintree,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaymentMethod {
    // A credit card or debit card, including those from Apple Pay and Google Pay
    Card,
    // A SEPA debit account
    SepaDebit,
    // An iDEAL account
    Ideal,
    // A PayPal account
    PayPal,
    GooglePlayBilling,
    AppleAppStore,
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
#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
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
