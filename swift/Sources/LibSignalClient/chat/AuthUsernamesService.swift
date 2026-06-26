//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public protocol AuthUsernamesService: Sendable {
    /// For the given encrypted username, generate a username link handle. The username link handle
    /// can be used to lookup the encrypted username.
    /// An account can only have one username link at a time; this endpoint overwrites the previous
    /// encrypted username if there was one.
    ///
    /// - Parameters:
    ///   - usernameCiphertext: must be between 1 and 128 bytes
    ///   - keepLinkHandle: If true and the account already had an encrypted username stored, the existing link handle will be reused. Otherwise a new link handle will be created.
    /// - Throws:
    ///   - ``SignalError/usernameNotSet(_:)`` if the account didn't have a username set
    ///   - the standard Signal network errors
    func setUsernameLink(
        usernameCiphertext: Data,
        keepLinkHandle: Bool,
    ) async throws -> UUID

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

    public func setUsernameLink(usernameCiphertext: Data, keepLinkHandle: Bool) async throws -> UUID {
        return try await NativeNice.AuthenticatedChatConnection_set_username_link(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            usernameCiphertext: usernameCiphertext,
            keepLinkHandle: keepLinkHandle,
        )
    }

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
