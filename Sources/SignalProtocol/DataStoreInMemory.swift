class InMemorySignalProtocolStore: IdentityKeyStore, PreKeyStore, SignedPreKeyStore, SessionStore, SenderKeyStore {
    private var publicKeys: [ProtocolAddress: IdentityKey] = [:]
    private var privateKey: IdentityKeyPair
    private var deviceId: UInt32
    private var prekeyMap: [UInt32: PreKeyRecord] = [:]
    private var signedPrekeyMap: [UInt32: SignedPreKeyRecord] = [:]
    private var sessionMap: [ProtocolAddress: SessionRecord] = [:]
    private var senderKeyMap: [SenderKeyName: SenderKeyRecord] = [:]

    init() throws {
        privateKey = try IdentityKeyPair.generate()
        deviceId = UInt32.random(in: 0...65535)
    }

    func identityKeyPair(context: UnsafeMutableRawPointer?) throws -> IdentityKeyPair {
        return privateKey
    }

    func localRegistrationId(context: UnsafeMutableRawPointer?) throws -> UInt32 {
        return deviceId
    }

    func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws -> Bool {
        if publicKeys.updateValue(identity, forKey: address) == nil {
            return false; // newly created
        } else {
            return true
        }
    }

    func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, direction: Direction, context: UnsafeMutableRawPointer?) throws -> Bool {
        if let pk = publicKeys[address] {
            return pk == identity
        } else {
            return true // tofu
        }
    }

    func identity(for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws -> IdentityKey? {
        return publicKeys[address]
    }

    func loadPreKey(id: UInt32, context: UnsafeMutableRawPointer?) throws -> PreKeyRecord {
        if let record = prekeyMap[id] {
            return record
        } else {
            throw SignalError.invalidKeyIdentifier("no prekey with this identifier")
        }
    }

    func storePreKey(_ record: PreKeyRecord, id: UInt32, context: UnsafeMutableRawPointer?) throws {
        prekeyMap[id] = record
    }

    func removePreKey(id: UInt32, context: UnsafeMutableRawPointer?) throws {
        prekeyMap.removeValue(forKey: id)
    }

    func loadSignedPreKey(id: UInt32, context: UnsafeMutableRawPointer?) throws -> SignedPreKeyRecord {
        if let record = signedPrekeyMap[id] {
            return record
        } else {
            throw SignalError.invalidKeyIdentifier("no signed prekey with this identifier")
        }
    }

    func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context: UnsafeMutableRawPointer?) throws {
        signedPrekeyMap[id] = record
    }

    func loadSession(for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws -> SessionRecord? {
        return sessionMap[address]
    }

    func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws {
        sessionMap[address] = record
    }

    func storeSenderKey(name: SenderKeyName, record: SenderKeyRecord, context: UnsafeMutableRawPointer?) throws {
        senderKeyMap[name] = record
    }

    func loadSenderKey(name: SenderKeyName, context: UnsafeMutableRawPointer?) throws -> SenderKeyRecord? {
        return senderKeyMap[name]
    }
}
