//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// A dummy StoreContext usable with InMemorySignalProtocolStore.
public struct NullContext: StoreContext {
    public init() {}
}

private struct SenderKeyName: Hashable {
    var sender: ProtocolAddress
    var distributionId: UUID
}

public class InMemorySignalProtocolStore: IdentityKeyStore, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore, SessionStore, SenderKeyStore {
    private var publicKeys: [ProtocolAddress: IdentityKey] = [:]
    private var privateKey: IdentityKeyPair
    private var registrationId: UInt32
    private var prekeyMap: [UInt32: PreKeyRecord] = [:]
    private var signedPrekeyMap: [UInt32: SignedPreKeyRecord] = [:]
    private var kyberPrekeyMap: [UInt32: KyberPreKeyRecord] = [:]
    private var kyberPrekeysUsed: Set<UInt32> = []
    private var sessionMap: [ProtocolAddress: SessionRecord] = [:]
    private var senderKeyMap: [SenderKeyName: SenderKeyRecord] = [:]

    public init() {
        privateKey = IdentityKeyPair.generate()
        registrationId = UInt32.random(in: 0...0x3FFF)
    }

    public init(identity: IdentityKeyPair, registrationId: UInt32) {
        self.privateKey = identity
        self.registrationId = registrationId
    }

    public func identityKeyPair(context: StoreContext) throws -> IdentityKeyPair {
        return privateKey
    }

    public func localRegistrationId(context: StoreContext) throws -> UInt32 {
        return registrationId
    }

    public func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context: StoreContext) throws -> Bool {
        if publicKeys.updateValue(identity, forKey: address) == nil {
            return false // newly created
        } else {
            return true
        }
    }

    public func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, direction: Direction, context: StoreContext) throws -> Bool {
        if let pk = publicKeys[address] {
            return pk == identity
        } else {
            return true // tofu
        }
    }

    public func identity(for address: ProtocolAddress, context: StoreContext) throws -> IdentityKey? {
        return publicKeys[address]
    }

    public func loadPreKey(id: UInt32, context: StoreContext) throws -> PreKeyRecord {
        if let record = prekeyMap[id] {
            return record
        } else {
            throw SignalError.invalidKeyIdentifier("no prekey with this identifier")
        }
    }

    public func storePreKey(_ record: PreKeyRecord, id: UInt32, context: StoreContext) throws {
        prekeyMap[id] = record
    }

    public func removePreKey(id: UInt32, context: StoreContext) throws {
        prekeyMap.removeValue(forKey: id)
    }

    public func loadSignedPreKey(id: UInt32, context: StoreContext) throws -> SignedPreKeyRecord {
        if let record = signedPrekeyMap[id] {
            return record
        } else {
            throw SignalError.invalidKeyIdentifier("no signed prekey with this identifier")
        }
    }

    public func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context: StoreContext) throws {
        signedPrekeyMap[id] = record
    }

    public func loadKyberPreKey(id: UInt32, context: StoreContext) throws -> KyberPreKeyRecord {
        if let record = kyberPrekeyMap[id] {
            return record
        } else {
            throw SignalError.invalidKeyIdentifier("no kyber prekey with this identifier")
        }
    }

    public func storeKyberPreKey(_ record: KyberPreKeyRecord, id: UInt32, context: StoreContext) throws {
        kyberPrekeyMap[id] = record
    }

    public func markKyberPreKeyUsed(id: UInt32, context: StoreContext) throws {
        kyberPrekeysUsed.insert(id)
    }

    public func loadSession(for address: ProtocolAddress, context: StoreContext) throws -> SessionRecord? {
        return sessionMap[address]
    }

    public func loadExistingSessions(for addresses: [ProtocolAddress], context: StoreContext) throws -> [SessionRecord] {
        return try addresses.map { address in
            if let session = sessionMap[address] {
                return session
            }
            throw SignalError.sessionNotFound("\(address)")
        }
    }

    public func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: StoreContext) throws {
        sessionMap[address] = record
    }

    public func storeSenderKey(from sender: ProtocolAddress, distributionId: UUID, record: SenderKeyRecord, context: StoreContext) throws {
        senderKeyMap[SenderKeyName(sender: sender, distributionId: distributionId)] = record
    }

    public func loadSenderKey(from sender: ProtocolAddress, distributionId: UUID, context: StoreContext) throws -> SenderKeyRecord? {
        return senderKeyMap[SenderKeyName(sender: sender, distributionId: distributionId)]
    }
}
