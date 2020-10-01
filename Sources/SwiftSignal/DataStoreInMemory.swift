
class InMemoryIdentityKeyStore : IdentityKeyStore {
    private var public_keys : [ProtocolAddress : IdentityKey] = [:]
    private var private_key : IdentityKeyPair;
    private var device_id : UInt32;

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
        return public_keys[address] == identity
    }

    func getIdentity(address: ProtocolAddress, ctx: UnsafeMutableRawPointer?) throws -> Optional<IdentityKey> {
        return public_keys[address]
    }
}


class InMemoryPreKeyStore : PreKeyStore {
    private var map : [UInt32 : PreKeyRecord] = [:]

    func loadPreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws -> PreKeyRecord {
        if let record = map[id] {
            return record;
        } else {
            throw SignalError.invalid_key_identifier("no prekey with this identifier")
        }
    }

    func storePreKey(id: UInt32, record: PreKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        map[id] = record;
    }

    func removePreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws {
        map.removeValue(forKey: id)
    }
}

class InMemorySignedPreKeyStore : SignedPreKeyStore {
    private var map : [UInt32 : SignedPreKeyRecord] = [:]

    func loadSignedPreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws -> SignedPreKeyRecord {
        if let record = map[id] {
            return record;
        } else {
            throw SignalError.invalid_key_identifier("no signed prekey with this identifier")
        }
    }

    func storeSignedPreKey(id: UInt32, record: SignedPreKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        map[id] = record;
    }
}

class InMemorySessionStore : SessionStore {
    private var map : [ProtocolAddress: SessionRecord] = [:]

    func loadSession(address: ProtocolAddress, ctx: UnsafeMutableRawPointer?) throws -> Optional<SessionRecord> {
        return map[address];
    }

    func storeSession(address: ProtocolAddress, record: SessionRecord, ctx: UnsafeMutableRawPointer?) throws {
        map[address] = record;
    }
}


class InMemorySenderKeyStore : SenderKeyStore {
    private var map : [SenderKeyName : SenderKeyRecord] = [:]

    func storeSenderKey(name: SenderKeyName, record: SenderKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        map[name] = record
    }
    func loadSenderKey(name: SenderKeyName, ctx: UnsafeMutableRawPointer?) throws -> SenderKeyRecord? {
        return map[name]
    }
}
