//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public protocol UnauthUsernamesService: Sendable {
    /// Looks up a username hash on the service, like that computed by ``Username``.
    ///
    /// Returns the corresponding account's ACI, or `nil` if the username doesn't correspond to an
    /// account.
    ///
    /// Throws only if the request can't be completed, potentially including if the hash is
    /// structurally invalid.
    func lookUpUsernameHash(_ hash: UsernameHash) async throws -> Aci?

    /// Looks up a username link on the service by UUID.
    ///
    /// Returns a decrypted, validated username, or `nil` if the UUID does not correspond to a
    /// username link (perhaps the user rotated their link).
    ///
    /// Throws if the request can't be completed. Specifically throws
    /// ``SignalError/usernameLinkInvalidEntropyDataLength(_:)`` if the entropy is invalid, and
    /// ``SignalError/usernameLinkInvalid(_:)`` if the data fetched from the service could not be
    /// decrypted or did not contain a valid username.
    func lookUpUsernameLink(_ uuid: UUID, entropy: Data) async throws -> Username?
}

extension UnauthenticatedChatConnection: UnauthUsernamesService {
    public func lookUpUsernameHash(_ hash: Data) async throws -> Aci? {
        let uuid = try await NativeNice.UnauthenticatedChatConnection_look_up_username_hash(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            hash: hash
        )
        return uuid.map { Aci(fromUUID: $0) }
    }

    public func lookUpUsernameLink(_ uuid: UUID, entropy: Data) async throws -> Username? {
        let response = try await NativeNice.UnauthenticatedChatConnection_look_up_username_link(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            uuid: uuid,
            entropy: entropy
        )
        return response.map { name, hash in Username(name, uncheckedHash: hash) }
    }
}

extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthUsernamesService> {
    public static var usernames: Self { .init() }
}
