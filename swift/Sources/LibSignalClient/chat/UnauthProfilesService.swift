//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public protocol UnauthProfilesService: Sendable {
    /// Does an account with the given ACI or PNI exist?
    ///
    /// Throws only if the request can't be completed.
    func accountExists(_ account: ServiceId) async throws -> Bool
}

extension UnauthenticatedChatConnection: UnauthProfilesService {
    public func accountExists(_ account: ServiceId) async throws -> Bool {
        return try await self.tokioAsyncContext
            .invokeAsyncFunction { promise, tokioAsyncContext in
                withNativeHandle { chatService in
                    account.withPointerToFixedWidthBinary { account in
                        signal_unauthenticated_chat_connection_account_exists(
                            promise,
                            tokioAsyncContext.const(),
                            chatService.const(),
                            account
                        )
                    }
                }
            }
    }
}

extension UnauthServiceSelector where Self == UnauthServiceSelectorHelper<any UnauthProfilesService> {
    public static var profiles: Self { .init() }
}
