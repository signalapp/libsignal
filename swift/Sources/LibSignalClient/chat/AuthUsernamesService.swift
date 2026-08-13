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

    /// Sets the account's username to a previously-reserved value (see
    /// ``reserveUsernameHashes(_:)``), along with the encrypted username for the account's
    /// username link.
    ///
    /// The zero-knowledge proof that must accompany the username hash is generated internally.
    ///
    /// - Parameters:
    ///   - username: The username whose previously-reserved hash should be claimed
    ///   - usernameCiphertext: The encrypted username for the account's username link; must be between 1 and 128 bytes
    /// - Returns: The server-generated username link handle for the newly-confirmed username
    /// - Throws:
    ///   - ``SignalError/usernameReservationNotFound(_:)`` if the username's hash was not reserved for this account
    ///   - ``SignalError/usernameNotAvailable(_:)`` if the reservation lapsed and the username was claimed by another account
    ///   - the standard Signal network errors
    func confirmUsername(
        _ username: Username,
        usernameCiphertext: Data,
    ) async throws -> UUID

    /// Clears the current username hash, ciphertext, and link for the authenticated account.
    ///
    /// This also succeeds if the account has no username set, so a caller retrying a deletion
    /// sees the same result as the original call.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func deleteUsernameHash() async throws

    /// Clears any username link associated with the authenticated account.
    ///
    /// The previously stored encrypted username is deleted and the link handle is deactivated;
    /// the account's username hash (if any) is left in place. This also succeeds if the account
    /// has no username link, so a caller retrying a deletion sees the same result as the
    /// original call.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func deleteUsernameLink() async throws
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

    public func confirmUsername(
        _ username: Username,
        usernameCiphertext: Data,
    ) async throws -> UUID {
        return try await self.confirmUsername(
            username,
            usernameCiphertext: usernameCiphertext,
            rngForTesting: -1,
        )
    }

    public func deleteUsernameHash() async throws {
        return try await NativeNice.AuthenticatedChatConnection_delete_username_hash(
            asyncContext: self.tokioAsyncContext,
            chat: self,
        )
    }

    public func deleteUsernameLink() async throws {
        return try await NativeNice.AuthenticatedChatConnection_delete_username_link(
            asyncContext: self.tokioAsyncContext,
            chat: self,
        )
    }
}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthUsernamesService> {
    public static var usernames: Self { .init() }
}

internal protocol AuthUsernamesServiceImpl: Sendable {
    func confirmUsername(
        _ username: Username,
        usernameCiphertext: Data,
        rngForTesting: Int64,
    ) async throws -> UUID
}

extension AuthenticatedChatConnection: AuthUsernamesServiceImpl {
    func confirmUsername(
        _ username: Username,
        usernameCiphertext: Data,
        rngForTesting: Int64,
    ) async throws -> UUID {
        return try await NativeNice.AuthenticatedChatConnection_confirm_username(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            username: username.value,
            usernameCiphertext: usernameCiphertext,
            rng: rngForTesting,
        )
    }
}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthUsernamesServiceImpl> {
    internal static var usernamesImpl: Self { .init() }
}
