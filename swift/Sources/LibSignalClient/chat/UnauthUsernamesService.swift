//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public protocol UnauthUsernamesService: Sendable {
    /// Looks up a username hash on the service, like that computed by ``Username``.
    ///
    /// Returns the corresponding account's ACI, or `nil` if the username doesn't correspond to an
    /// account.
    ///
    /// Throws only if the request can't be completed, potentially including if the hash is
    /// structurally invalid.
    func lookUpUsernameHash(_ hash: Data) async throws -> Aci?

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
        let rawResponse: SignalOptionalUuid = try await self.tokioAsyncContext
            .invokeAsyncFunction { promise, tokioAsyncContext in
                withNativeHandle { chatService in
                    hash.withUnsafeBorrowedBuffer { hash in
                        signal_unauthenticated_chat_connection_look_up_username_hash(
                            promise,
                            tokioAsyncContext.const(),
                            chatService.const(),
                            hash
                        )
                    }
                }
            }
        let uuid = try! invokeFnReturningOptionalUuid { out in
            out?.pointee = rawResponse
            return nil
        }
        return uuid.map { Aci(fromUUID: $0) }
    }

    public func lookUpUsernameLink(_ uuid: UUID, entropy: Data) async throws -> Username? {
        var rawResponse: SignalOptionalPairOfc_charu832 = try await self.tokioAsyncContext
            .invokeAsyncFunction { promise, tokioAsyncContext in
                withNativeHandle { chatService in
                    try! withAllBorrowed(uuid, entropy) { uuid, entropy in
                        signal_unauthenticated_chat_connection_look_up_username_link(
                            promise,
                            tokioAsyncContext.const(),
                            chatService.const(),
                            uuid,
                            entropy
                        )
                    }
                }
            }
        guard rawResponse.present else {
            return nil
        }
        defer { signal_free_string(rawResponse.first) }
        let name = String(cString: rawResponse.first!)
        let hash = withUnsafeBytes(of: &rawResponse.second) { Data($0) }
        return Username(name, uncheckedHash: hash)
    }
}

extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthUsernamesService> {
    public static var usernames: Self { .init() }
}
