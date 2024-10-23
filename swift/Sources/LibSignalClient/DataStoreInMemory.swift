//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation

/// A dummy StoreContext usable with InMemorySignalProtocolStore.
public struct NullContext: StoreContext, Sendable {
    public init() {}
}

private struct SenderKeyName: Hashable {
    var sender: ProtocolAddress
    var distributionId: UUID
}

open class InMemorySignalProtocolStore: IdentityKeyStore, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore, SessionStore, SenderKeyStore {
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
        self.privateKey = IdentityKeyPair.generate()
        self.registrationId = UInt32.random(in: 0...0x3FFF)
    }

    public init(identity: IdentityKeyPair, registrationId: UInt32) {
        self.privateKey = identity
        self.registrationId = registrationId
    }

    open func identityKeyPair(context: StoreContext) throws -> IdentityKeyPair {
        return self.privateKey
    }

    open func localRegistrationId(context: StoreContext) throws -> UInt32 {
        return self.registrationId
    }

    open func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context: StoreContext) throws -> Bool {
        if self.publicKeys.updateValue(identity, forKey: address) == nil {
            return false // newly created
        } else {
            return true
        }
    }

    open func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, direction: Direction, context: StoreContext) throws -> Bool {
        if let pk = publicKeys[address] {
            return pk == identity
        } else {
            return true // tofu
        }
    }

    open func identity(for address: ProtocolAddress, context: StoreContext) throws -> IdentityKey? {
        return self.publicKeys[address]
    }

    open func loadPreKey(id: UInt32, context: StoreContext) throws -> PreKeyRecord {
        if let record = prekeyMap[id] {
            return record
        } else {
            throw SignalError.invalidKeyIdentifier("no prekey with this identifier")
        }
    }

    open func storePreKey(_ record: PreKeyRecord, id: UInt32, context: StoreContext) throws {
        self.prekeyMap[id] = record
    }

    open func removePreKey(id: UInt32, context: StoreContext) throws {
        self.prekeyMap.removeValue(forKey: id)
    }

    open func loadSignedPreKey(id: UInt32, context: StoreContext) throws -> SignedPreKeyRecord {
        if let record = signedPrekeyMap[id] {
            return record
        } else {
            throw SignalError.invalidKeyIdentifier("no signed prekey with this identifier")
        }
    }

    open func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context: StoreContext) throws {
        self.signedPrekeyMap[id] = record
    }

    open func loadKyberPreKey(id: UInt32, context: StoreContext) throws -> KyberPreKeyRecord {
        if let record = kyberPrekeyMap[id] {
            return record
        } else {
            throw SignalError.invalidKeyIdentifier("no kyber prekey with this identifier")
        }
    }

    open func storeKyberPreKey(_ record: KyberPreKeyRecord, id: UInt32, context: StoreContext) throws {
        self.kyberPrekeyMap[id] = record
    }

    open func markKyberPreKeyUsed(id: UInt32, context: StoreContext) throws {
        self.kyberPrekeysUsed.insert(id)
    }

    open func loadSession(for address: ProtocolAddress, context: StoreContext) throws -> SessionRecord? {
        return self.sessionMap[address]
    }

    open func loadExistingSessions(for addresses: [ProtocolAddress], context: StoreContext) throws -> [SessionRecord] {
        return try addresses.map { address in
            if let session = sessionMap[address] {
                return session
            }
            throw SignalError.sessionNotFound("\(address)")
        }
    }

    open func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: StoreContext) throws {
        self.sessionMap[address] = record
    }

    open func storeSenderKey(from sender: ProtocolAddress, distributionId: UUID, record: SenderKeyRecord, context: StoreContext) throws {
        self.senderKeyMap[SenderKeyName(sender: sender, distributionId: distributionId)] = record
    }

    open func loadSenderKey(from sender: ProtocolAddress, distributionId: UUID, context: StoreContext) throws -> SenderKeyRecord? {
        return self.senderKeyMap[SenderKeyName(sender: sender, distributionId: distributionId)]
    }
}
