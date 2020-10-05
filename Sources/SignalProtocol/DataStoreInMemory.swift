
class InMemorySignalProtocolStore : IdentityKeyStore, PreKeyStore, SignedPreKeyStore, SessionStore, SenderKeyStore {
    private var public_keys : [ProtocolAddress : IdentityKey] = [:]
    private var private_key : IdentityKeyPair;
    private var device_id : UInt32;
    private var prekey_map : [UInt32 : PreKeyRecord] = [:]
    private var signed_prekey_map : [UInt32 : SignedPreKeyRecord] = [:]
    private var session_map : [ProtocolAddress: SessionRecord] = [:]
    private var sender_key_map : [SenderKeyName : SenderKeyRecord] = [:]

    init() throws {
        private_key = try IdentityKeyPair();
        device_id = UInt32.random(in: 0...65535)
    }

    func getIdentityKeyPair(ctx: UnsafeMutableRawPointer?) throws -> IdentityKeyPair {
        return private_key
    }

    func getLocalRegistrationId(ctx: UnsafeMutableRawPointer?) throws -> UInt32 {
        return device_id
    }

    func saveIdentity(address: ProtocolAddress, identity: IdentityKey, ctx: UnsafeMutableRawPointer?) throws -> Bool {
        if public_keys.updateValue(identity, forKey: address) == nil {
            return false; // newly created
        } else {
            return true;
        }
    }

    func isTrustedIdentity(address: ProtocolAddress, identity: IdentityKey, direction: Direction, ctx: UnsafeMutableRawPointer?) throws -> Bool {
        if let pk = public_keys[address] {
            return pk == identity
        } else {
            return true // tofu
        }
    }

    func getIdentity(address: ProtocolAddress, ctx: UnsafeMutableRawPointer?) throws -> Optional<IdentityKey> {
        return public_keys[address]
    }

    func loadPreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws -> PreKeyRecord {
        if let record = prekey_map[id] {
            return record;
        } else {
            throw SignalError.invalidKeyIdentifier("no prekey with this identifier")
        }
    }

    func storePreKey(id: UInt32, record: PreKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        prekey_map[id] = record;
    }

    func removePreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws {
        prekey_map.removeValue(forKey: id)
    }

    func loadSignedPreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws -> SignedPreKeyRecord {
        if let record = signed_prekey_map[id] {
            return record;
        } else {
            throw SignalError.invalidKeyIdentifier("no signed prekey with this identifier")
        }
    }

    func storeSignedPreKey(id: UInt32, record: SignedPreKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        signed_prekey_map[id] = record;
    }

    func loadSession(address: ProtocolAddress, ctx: UnsafeMutableRawPointer?) throws -> Optional<SessionRecord> {
        return session_map[address];
    }

    func storeSession(address: ProtocolAddress, record: SessionRecord, ctx: UnsafeMutableRawPointer?) throws {
        session_map[address] = record;
    }

    func storeSenderKey(name: SenderKeyName, record: SenderKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        sender_key_map[name] = record
    }
    func loadSenderKey(name: SenderKeyName, ctx: UnsafeMutableRawPointer?) throws -> SenderKeyRecord? {
        return sender_key_map[name]
    }
}
