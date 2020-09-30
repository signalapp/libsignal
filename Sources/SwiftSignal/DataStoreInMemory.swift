
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

    func getPreKey(prekeyId: UInt32, ctx: UnsafeMutableRawPointer?) throws -> PreKeyRecord {
        if let record = map[prekeyId] {
            return record;
        } else {
            throw SignalError.invalid_key_identifier("no prekey with this identifier")
        }
    }

    func savePreKey(prekeyId: UInt32, record: PreKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        map[prekeyId] = record;
    }

    func removePreKey(prekeyId: UInt32, ctx: UnsafeMutableRawPointer?) throws {
        map.removeValue(forKey: prekeyId)
    }
}

class InMemorySignedPreKeyStore : SignedPreKeyStore {
    private var map : [UInt32 : SignedPreKeyRecord] = [:]

    func getSignedPreKey(signedPrekeyId: UInt32, ctx: UnsafeMutableRawPointer?) throws -> SignedPreKeyRecord {
        if let record = map[signedPrekeyId] {
            return record;
        } else {
            throw SignalError.invalid_key_identifier("no signed prekey with this identifier")
        }
    }

    func saveSignedPreKey(signedPrekeyId: UInt32, record: SignedPreKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        map[signedPrekeyId] = record;
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

    func saveSenderKey(name: SenderKeyName, record: SenderKeyRecord, ctx: UnsafeMutableRawPointer?) throws {
        map[name] = record
    }
    func loadSenderKey(name: SenderKeyName, ctx: UnsafeMutableRawPointer?) throws -> SenderKeyRecord? {
        return map[name]
    }
}
