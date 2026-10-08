//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public protocol AuthDonationsService: Sendable {
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
