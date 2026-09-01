//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

public struct PreKeyCounts: Equatable, Sendable {
    /// The approximate number of one-time EC pre-keys stored for the
    /// authenticated device and associated with the caller's ACI.
    public let aciEcPreKeyCount: UInt32
    /// The approximate number of one-time KEM pre-keys stored for the
    /// authenticated device and associated with the caller's ACI.
    public let aciKemPreKeyCount: UInt32
    /// The approximate number of one-time EC pre-keys stored for the
    /// authenticated device and associated with the caller's PNI.
    public let pniEcPreKeyCount: UInt32
    /// The approximate number of one-time KEM pre-keys stored for the
    /// authenticated device and associated with the caller's PNI.
    public let pniKemPreKeyCount: UInt32

    public init(
        aciEcPreKeyCount: UInt32,
        aciKemPreKeyCount: UInt32,
        pniEcPreKeyCount: UInt32,
        pniKemPreKeyCount: UInt32
    ) {
        self.aciEcPreKeyCount = aciEcPreKeyCount
        self.aciKemPreKeyCount = aciKemPreKeyCount
        self.pniEcPreKeyCount = pniEcPreKeyCount
        self.pniKemPreKeyCount = pniKemPreKeyCount
    }

    internal static func fromInternal(_ it: BridgePreKeyCounts) -> PreKeyCounts {
        PreKeyCounts(
            aciEcPreKeyCount: UInt32(exactly: it.aciEcPreKeyCount)!,
            aciKemPreKeyCount: UInt32(exactly: it.aciKemPreKeyCount)!,
            pniEcPreKeyCount: UInt32(exactly: it.pniEcPreKeyCount)!,
            pniKemPreKeyCount: UInt32(exactly: it.pniKemPreKeyCount)!,
        )
    }
}

public protocol AuthKeysService: Sendable {
    /// Retrieves an approximate count of the number of the various kinds of
    /// one-time pre-keys stored for the authenticated device.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func getPreKeyCount() async throws -> PreKeyCounts
}

extension AuthenticatedChatConnection: AuthKeysService {

    public func getPreKeyCount() async throws -> PreKeyCounts {
        return PreKeyCounts.fromInternal(
            try await NativeNice.AuthenticatedChatConnection_get_pre_key_count(
                asyncContext: self.tokioAsyncContext,
                chat: self,
            )
        )
    }

}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthKeysService> {
    public static var keys: Self { .init() }
}
