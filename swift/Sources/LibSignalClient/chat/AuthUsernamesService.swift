//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public protocol AuthUsernamesService: Sendable {
    /// Given a prioritized list of between 1 and 20 username hashes, try reserving them (in order)
    ///
    /// The first successfully reserved hash will be returned.
    ///
    /// - Parameters:
    ///   - hashes: Must contain between 1 and 20 usernames
    /// - Throws:
    ///   - ``SignalError/usernameNotAvailable(_:)`` if none of the usernames were available
    ///   - the standard Signal network errors
    func reserveUsernameHashes(_ hashes: [UsernameHash]) async throws -> UsernameHash
}

extension AuthenticatedChatConnection: AuthUsernamesService {
    public func reserveUsernameHashes(_ hashes: [UsernameHash]) async throws -> UsernameHash {
        return try await NativeNice.AuthenticatedChatConnection_reserve_username_hash(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            usernameHashes: hashes
        )
    }
}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthUsernamesService> {
    public static var usernames: Self { .init() }
}
