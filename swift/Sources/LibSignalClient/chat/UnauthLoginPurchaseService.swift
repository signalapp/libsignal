//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public enum PaymentProvider: Sendable, Equatable {
    case googlePlayBilling
    case appleAppStore
    case stripe
    case braintree
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
public struct ChargeFailure: Sendable, Equatable {
    public var processor: PaymentProvider
    /// See [Stripe failure codes](https://stripe.com/docs/api/charges/object#charge_object-failure_code)
    /// or [Braintree decline codes](https://developer.paypal.com/braintree/docs/reference/general/processor-responses/authorization-responses#decline-codes)
    /// depending on which processor was used
    public var code: String
    /// See [Stripe failure codes](https://stripe.com/docs/api/charges/object#charge_object-failure_code)
    /// or [Braintree decline codes](https://developer.paypal.com/braintree/docs/reference/general/processor-responses/authorization-responses#decline-codes)
    /// depending on which processor was used
    public var message: String
    /// See [Outcome Network Status](https://stripe.com/docs/api/charges/object#charge_object-outcome-network_status)
    public var outcomeNetworkStatus: String?
    /// See [Outcome Reason](https://stripe.com/docs/api/charges/object#charge_object-outcome-reason)
    public var outcomeReason: String?
    /// See [Outcome Type](https://stripe.com/docs/api/charges/object#charge_object-outcome-type)
    public var outcomeType: String?

    public init(
        processor: PaymentProvider,
        code: String,
        message: String,
        outcomeNetworkStatus: String? = nil,
        outcomeReason: String? = nil,
        outcomeType: String? = nil
    ) {
        self.processor = processor
        self.code = code
        self.message = message
        self.outcomeNetworkStatus = outcomeNetworkStatus
        self.outcomeReason = outcomeReason
        self.outcomeType = outcomeType
    }
}

public protocol UnauthLoginPurchaseService: Sendable {
    /// Obtain a ZK receipt credential for a completed one-time login payment.
    /// The receipt credential can then be presented at registration.
    /// subsequent retries to create a login credential for the same ``purchaseIdentifier`` must use
    /// an identical ``receiptCredentialRequestContext``.
    ///
    /// - Throws:
    ///   - ``SignalError/ReceiptCredentialErrorPaymentRequired(_:)`` if the purchase is still pending with the payment provider. The client may retry later.
    ///   - ``SignalError/ReceiptCredentialErrorPaymentNotFound(_:)`` if the purchase did not complete successfully.
    ///   - ``SignalError/ReceiptCredentialErrorPaymentStillProcessing(_:)`` if the payment provider has no purchase with the provided ``purchaseIdentifier``
    ///   - ``SignalError/ReceiptCredentialErrorReceiptAlreadyIssued(_:)`` if the purchase was already redeemed for a receipt credential, but with a different receipt credential request
    ///   - the standard Signal network errors
    func createLoginReceiptCredential(
        paymentProcessor: PaymentProvider,
        purchaseIdentifier: String,
        receiptCredentialRequestContext: ReceiptCredentialRequestContext,
        serverParams: ServerPublicParams,
        purchaseTime: Date,
    ) async throws -> ReceiptCredential
}

extension UnauthenticatedChatConnection: UnauthLoginPurchaseService {
    public func createLoginReceiptCredential(
        paymentProcessor: PaymentProvider,
        purchaseIdentifier: String,
        receiptCredentialRequestContext: ReceiptCredentialRequestContext,
        serverParams: ServerPublicParams,
        purchaseTime: Date,
    ) async throws -> ReceiptCredential {
        return try await NativeNice.UnauthenticatedChatConnection_create_login_receipt_credential(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            paymentProcessor: paymentProcessor,
            purchaseIdentifier: purchaseIdentifier,
            receiptCredentialRequestContext: receiptCredentialRequestContext,
            serverParams: serverParams,
            purchaseTime: purchaseTime,
        )
    }

}

extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthLoginPurchaseService> {
    public static var loginPurchase: Self { .init() }
}
