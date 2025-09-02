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
}

extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthUsernamesService> {
    public static var usernames: Self { .init() }
}
