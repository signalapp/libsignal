//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// How a redeemed badge should appear on the account's profile.
public enum BadgeVisibility: Sendable {
    // Must be kept in sync with BadgeVisibility in rust/bridge/shared/types/src/net/chat.rs.
    // The generated bridging code uses this type directly and refers to the cases by name.
    /// Don't make the badge visible. A new badge starts out hidden, and a badge the account already
    /// shows stays visible.
    case doNotSet
    /// Make the badge visible on the profile.
    case setVisible
    /// Make the badge visible on the profile as the primary badge.
    case setPrimary
}

public protocol AuthDonationsService: Sendable {
    /// Redeems a donation receipt to add the corresponding badge to the account.
    ///
    /// After this succeeds, the account has the badge until the receipt's expiration time.
    /// `badgeVisibility` controls whether it shows on the profile; see ``BadgeVisibility``.
    ///
    /// Redeeming the same receipt again for the same account succeeds. A receipt that was already
    /// redeemed by a different account fails with ``SignalError/receiptAlreadyRedeemed(_:)``.
    ///
    /// - Throws:
    ///   - ``SignalError/invalidReceipt(_:)`` if the receipt credential presentation is invalid
    ///   - ``SignalError/receiptAlreadyRedeemed(_:)`` if the receipt was already redeemed
    ///   - the standard Signal network errors
    func redeemDonationReceipt(
        _ presentation: ReceiptCredentialPresentation,
        badgeVisibility: BadgeVisibility,
    ) async throws

    /// Requests a batch of anonymous, single-use donation permits, one for each nonce in
    /// `requestContext`.
    ///
    /// The server's response is verified against `serverParams` before the permits are returned,
    /// in the same order as the nonces in `requestContext`.
    ///
    /// The server rate-limits each account by the number of permits requested, not the number of
    /// requests. If the account doesn't have enough allowance left for the whole batch, nothing is
    /// issued or used up and this fails with ``SignalError/rateLimitedError(retryAfter:message:)``.
    /// The retry delay is how long until the *full* batch would be allowed, so asking for fewer
    /// permits may succeed sooner, even right away. A batch larger than the server's maximum
    /// allowance will never succeed, no matter how long the caller waits.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func createDonationPermits(
        requestContext: DonationPermitRequestContext,
        serverParams: ServerPublicParams,
    ) async throws -> [DonationPermit]
}

extension AuthenticatedChatConnection: AuthDonationsService {
    public func redeemDonationReceipt(
        _ presentation: ReceiptCredentialPresentation,
        badgeVisibility: BadgeVisibility,
    ) async throws {
        try await NativeNice.AuthenticatedChatConnection_redeem_donation_receipt(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            presentation: presentation,
            visibility: badgeVisibility,
        )
    }

    public func createDonationPermits(
        requestContext: DonationPermitRequestContext,
        serverParams: ServerPublicParams,
    ) async throws -> [DonationPermit] {
        return try await NativeNice.AuthenticatedChatConnection_create_donation_permits(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            requestContext: requestContext,
            serverParams: serverParams,
        )
    }
}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthDonationsService> {
    public static var donations: Self { .init() }
}
