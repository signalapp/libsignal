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

/// A one-time elliptic-curve pre-key, as uploaded to the server.
///
/// This is only the public half of the key; the private half never leaves the
/// device.
public struct PublicEcPreKey {
    /// A locally-unique identifier for this key, which peers using this key to
    /// encrypt messages will provide so the private key can be looked up.
    ///
    /// Must be less than `1 << 31` (`Int32.max`).
    public let keyId: UInt32
    /// The public key.
    public let publicKey: PublicKey

    public init(keyId: UInt32, publicKey: PublicKey) {
        self.keyId = keyId
        self.publicKey = publicKey
    }

    public init(_ record: PreKeyRecord) throws {
        self.init(keyId: record.id, publicKey: try record.publicKey())
    }
}

/// A one-time KEM pre-key, as uploaded to the server.
///
/// This is only the public half of the key; the private half never leaves the
/// device.
public struct PublicKemPreKey {
    /// A locally-unique identifier for this key, which peers using this key to
    /// encrypt messages will provide so the private key can be looked up.
    ///
    /// Must be less than `1 << 31` (`Int32.max`).
    public let keyId: UInt32
    /// The public key.
    public let publicKey: KEMPublicKey
    /// The signature of the public key by the appropriate identity key.
    public let signature: Data

    public init(keyId: UInt32, publicKey: KEMPublicKey, signature: Data) {
        self.keyId = keyId
        self.publicKey = publicKey
        self.signature = signature
    }

    public init(_ record: KyberPreKeyRecord) throws {
        self.init(keyId: record.id, publicKey: try record.publicKey(), signature: record.signature)
    }
}

public protocol AuthKeysService: Sendable {
    /// Retrieves an approximate count of the number of the various kinds of
    /// one-time pre-keys stored for the authenticated device.
    ///
    /// - Throws:
    ///   - the standard Signal network errors
    func getPreKeyCount() async throws -> PreKeyCounts

    /// Uploads a new set of one-time EC pre-keys for the authenticated device,
    /// clearing any previously-stored one-time EC pre-keys for `identity`.
    ///
    /// - Parameters:
    ///   - preKeys: Must contain between 1 and 100 keys
    /// - Throws:
    ///   - the standard Signal network errors
    func setOneTimeEcPreKeys(identity: ServiceIdKind, preKeys: [PublicEcPreKey]) async throws

    /// Uploads a new set of one-time KEM pre-keys for the authenticated device,
    /// clearing any previously-stored one-time KEM pre-keys for `identity`.
    ///
    /// - Parameters:
    ///   - preKeys: Must contain between 1 and 100 keys
    /// - Throws:
    ///   - the standard Signal network errors
    func setOneTimeKemPreKeys(identity: ServiceIdKind, preKeys: [PublicKemPreKey]) async throws
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

    public func setOneTimeEcPreKeys(identity: ServiceIdKind, preKeys: [PublicEcPreKey]) async throws {
        var ids = [UInt32]()
        ids.reserveCapacity(preKeys.count)
        var keys = [PublicKey]()
        keys.reserveCapacity(preKeys.count)

        for next in preKeys {
            ids.append(next.keyId)
            keys.append(next.publicKey)
        }

        return try await NativeNice.AuthenticatedChatConnection_set_one_time_ec_pre_keys(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            identityType: identity,
            preKeyIds: ids,
            preKeyData: keys,
        )
    }

    public func setOneTimeKemPreKeys(identity: ServiceIdKind, preKeys: [PublicKemPreKey]) async throws {
        var ids = [UInt32]()
        ids.reserveCapacity(preKeys.count)
        var keys = [KEMPublicKey]()
        keys.reserveCapacity(preKeys.count)
        var signatures = [Data]()
        signatures.reserveCapacity(preKeys.count)

        for next in preKeys {
            ids.append(next.keyId)
            keys.append(next.publicKey)
            signatures.append(next.signature)
        }

        return try await NativeNice.AuthenticatedChatConnection_set_one_time_kem_pre_keys(
            asyncContext: self.tokioAsyncContext,
            chat: self,
            identityType: identity,
            preKeyIds: ids,
            preKeyData: keys,
            preKeySignatures: signatures,
        )
    }

}

extension AuthServiceSelector where Self == AuthServiceSelectorHelper<any AuthKeysService> {
    public static var keys: Self { .init() }
}
