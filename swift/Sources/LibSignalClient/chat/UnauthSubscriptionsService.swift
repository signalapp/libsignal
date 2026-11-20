//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public protocol UnauthSubscriptionsService: Sendable {
    /// Obtain a ZK receipt credential for an active subscription.
    /// The receipt credential can then be used to obtain an entitlement (e.g. a badge or backup tier).
    ///
    /// Retries must use an identical `receiptCredentialRequestContext`. After successfully receiving
    /// the credential, the request context **must not** be reused again, or you may not be able to
    /// redeem a valid payment invoice.
    ///
    /// Note that you may in fact redeem *multiple* invoices for the same request context while
    /// retrying this operation if a later invoice gets paid while you are retrying. However, the
    /// returned receipt is always for the latest invoice, so it will have the latest expiration
    /// possible and no entitlement time will be lost.
    ///
    /// Clients **must** validate that the generated receipt credential's level matches their
    /// expectations. In particular, if you are currently at subscription level 100, and send a
    /// request to change to level 200, you may get a receipt for level 100 or level 200 until you
    /// get a successful response for the level change request. (Consider a successful level change
    /// request where the connection drops before the response makes it back to the client.)
    ///
    /// - Throws:
    ///   - ``SignalError/ReceiptCredentialErrorPaymentRequired(_:)`` if the purchase did not complete successfully.
    ///   - ``SignalError/ReceiptCredentialErrorPaymentStillProcessing(_:)`` if the most recent subscription renewal
    ///   has not happened yet. Retrying immediately is unlikely to help, but retrying later may succeed.
    ///   - ``SignalError/ReceiptCredentialErrorPaymentNotFound(_:)`` indicates either that the `subscriberId` is not
    ///   associated with an active subscription, or that the server has no record of `subscriberId` at all.
    ///   - ``SignalError/ReceiptCredentialErrorReceiptAlreadyIssued(_:)`` if the purchase was already redeemed for a receipt credential, but with a different receipt credential request.
    ///   - the standard Signal network errors
    func getSubscriptionReceiptCredential(
        subscriberId: Data,
        receiptCredentialRequestContext: ReceiptCredentialRequestContext,
        serverParams: ServerPublicParams,
    ) async throws -> ReceiptCredential

    /// Fetches information about Signal's in-app donations and purchases.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func getPurchaseProductConfiguration() async throws -> PurchaseProductConfiguration
}

extension UnauthenticatedChatConnection: UnauthSubscriptionsService {
    public func getSubscriptionReceiptCredential(
        subscriberId: Data,
        receiptCredentialRequestContext: ReceiptCredentialRequestContext,
        serverParams: ServerPublicParams,
    ) async throws -> ReceiptCredential {
        return try await NativeNice.UnauthenticatedChatConnection_get_subscription_receipt_credential(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            subscriberId: subscriberId,
            receiptCredentialRequestContext: receiptCredentialRequestContext,
            serverParams: serverParams,
        )
    }

    public func getPurchaseProductConfiguration() async throws -> PurchaseProductConfiguration {
        return try await NativeNice.UnauthenticatedChatConnection_get_product_configuration(
            asyncContext: self.tokioAsyncContext,
            chat: self
        )
    }
}

extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthSubscriptionsService> {
    public static var subscriptions: Self { .init() }
}
