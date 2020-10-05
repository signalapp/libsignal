
class InMemorySignalProtocolStore : IdentityKeyStore, PreKeyStore, SignedPreKeyStore, SessionStore, SenderKeyStore {
    private var publicKeys : [ProtocolAddress : IdentityKey] = [:]
    private var privateKey : IdentityKeyPair;
    private var deviceId : UInt32;
    private var prekeyMap : [UInt32 : PreKeyRecord] = [:]
    private var signedPrekeyMap : [UInt32 : SignedPreKeyRecord] = [:]
    private var sessionMap : [ProtocolAddress: SessionRecord] = [:]
    private var senderKeyMap : [SenderKeyName : SenderKeyRecord] = [:]

    init() throws {
        privateKey = try IdentityKeyPair();
        deviceId = UInt32.random(in: 0...65535)
    }

    func getIdentityKeyPair(ctx: UnsafeMutableRawPointer?) throws -> IdentityKeyPair {
        return privateKey
    }

    func getLocalRegistrationId(ctx: UnsafeMutableRawPointer?) throws -> UInt32 {
        return deviceId
    }

    func saveIdentity(address: ProtocolAddress, identity: IdentityKey, ctx: UnsafeMutableRawPointer?) throws -> Bool {
        if publicKeys.updateValue(identity, forKey: address) == nil {
            return false; // newly created
        } else {
            return true;
        }
    }

    func isTrustedIdentity(address: ProtocolAddress, identity: IdentityKey, direction: Direction, ctx: UnsafeMutableRawPointer?) throws -> Bool {
        if let pk = publicKeys[address] {
            return pk == identity
        } else {
            return true // tofu
        }
    }

    func getIdentity(address: ProtocolAddress, ctx: UnsafeMutableRawPointer?) throws -> Optional<IdentityKey> {
        return publicKeys[address]
    }

    func loadPreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws -> PreKeyRecord {
        if let record = prekeyMap[id] {
            return record;
        } else {
            throw SignalError.invalidKeyIdentifier("no prekey with this identifier")
        }
    }

    func storePreKey(id: UInt32, record: PreKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        prekeyMap[id] = record;
    }

    func removePreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws {
        prekeyMap.removeValue(forKey: id)
    }

    func loadSignedPreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws -> SignedPreKeyRecord {
        if let record = signedPrekeyMap[id] {
            return record;
        } else {
            throw SignalError.invalidKeyIdentifier("no signed prekey with this identifier")
        }
    }

    func storeSignedPreKey(id: UInt32, record: SignedPreKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        signedPrekeyMap[id] = record;
    }

    func loadSession(address: ProtocolAddress, ctx: UnsafeMutableRawPointer?) throws -> Optional<SessionRecord> {
        return sessionMap[address];
    }

    func storeSession(address: ProtocolAddress, record: SessionRecord, ctx: UnsafeMutableRawPointer?) throws {
        sessionMap[address] = record;
    }

    func storeSenderKey(name: SenderKeyName, record: SenderKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        senderKeyMap[name] = record
    }
    func loadSenderKey(name: SenderKeyName, ctx: UnsafeMutableRawPointer?) throws -> SenderKeyRecord? {
        return senderKeyMap[name]
    }
}
