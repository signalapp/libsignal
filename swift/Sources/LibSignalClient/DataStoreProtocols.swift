//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public enum Direction: Sendable {
    case sending
    case receiving
}

public enum IdentityChange: Sendable {
    case newOrUnchanged
    case replacedExisting
}

/// A marker protocol, which must be downcast to use in any particular store.
///
/// Essentially `Any`, but still able to catch typos when calling something that uses stores.
public protocol StoreContext {}

public protocol IdentityKeyStore: AnyObject {
    func identityKeyPair(context: StoreContext) throws -> IdentityKeyPair
    func localRegistrationId(context: StoreContext) throws -> UInt32
    /// Saves `identity` for `address`, which is then considered trusted.
    ///
    /// libsignal calls this after every successful decrypt on the active session, and after every
    /// encrypt, even when `identity` is unchanged. Implementations that track the identity of the
    /// last received message (see ``recordReceivedIdentity(_:for:context:)``) should update it
    /// here too.
    func saveIdentity(
        _ identity: IdentityKey,
        for address: ProtocolAddress,
        context: StoreContext
    ) throws -> IdentityChange
    func isTrustedIdentity(
        _ identity: IdentityKey,
        for address: ProtocolAddress,
        direction: Direction,
        context: StoreContext
    ) throws -> Bool
    func identity(for address: ProtocolAddress, context: StoreContext) throws -> IdentityKey?
    /// Records that a message from `address` was just decrypted under `identity` on an archived
    /// session.
    ///
    /// After the trust check, each successful decrypt calls exactly one of
    /// ``saveIdentity(_:for:context:)`` and this method: `saveIdentity` when the message was
    /// decrypted on the active session or established a new session, and this method when it was
    /// decrypted on an existing archived session. An archived session may belong to an identity
    /// that has since been replaced, so `identity` can differ from the saved identity.
    ///
    /// The default implementation does nothing.
    func recordReceivedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context: StoreContext) throws
}

extension IdentityKeyStore {
    public func recordReceivedIdentity(
        _ identity: IdentityKey,
        for address: ProtocolAddress,
        context: StoreContext
    ) throws {}
}

public protocol PreKeyStore: AnyObject {
    func loadPreKey(id: UInt32, context: StoreContext) throws -> PreKeyRecord
    func storePreKey(_ record: PreKeyRecord, id: UInt32, context: StoreContext) throws
    func removePreKey(id: UInt32, context: StoreContext) throws
}

public protocol SignedPreKeyStore: AnyObject {
    func loadSignedPreKey(id: UInt32, context: StoreContext) throws -> SignedPreKeyRecord
    func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context: StoreContext) throws
}

public protocol KyberPreKeyStore: AnyObject {
    func loadKyberPreKey(id: UInt32, context: StoreContext) throws -> KyberPreKeyRecord
    func storeKyberPreKey(_ record: KyberPreKeyRecord, id: UInt32, context: StoreContext) throws
    func markKyberPreKeyUsed(id: UInt32, signedPreKeyId: UInt32, baseKey: PublicKey, context: StoreContext) throws
}

public protocol SessionStore: AnyObject {
    func loadSession(for address: ProtocolAddress, context: StoreContext) throws -> SessionRecord?
    func loadExistingSessions(for addresses: [ProtocolAddress], context: StoreContext) throws -> [SessionRecord]
    func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: StoreContext) throws
}

public protocol SenderKeyStore: AnyObject {
    func storeSenderKey(
        from sender: ProtocolAddress,
        distributionId: UUID,
        record: SenderKeyRecord,
        context: StoreContext
    ) throws
    func loadSenderKey(
        from sender: ProtocolAddress,
        distributionId: UUID,
        context: StoreContext
    ) throws -> SenderKeyRecord?
}
