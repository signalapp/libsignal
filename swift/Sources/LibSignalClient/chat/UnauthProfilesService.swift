//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public protocol UnauthProfilesService: Sendable {
    /// Does an account with the given ACI or PNI exist?
    ///
    /// Throws only if the request can't be completed.
    func accountExists(_ account: ServiceId) async throws -> Bool
}

extension UnauthenticatedChatConnection: UnauthProfilesService {
    public func accountExists(_ account: ServiceId) async throws -> Bool {
        return try await NativeNice.UnauthenticatedChatConnection_account_exists(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            account: account
        )
    }
}

extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthProfilesService> {
    public static var profiles: Self { .init() }
}
