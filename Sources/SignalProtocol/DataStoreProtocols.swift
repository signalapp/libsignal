import SignalFfi

enum Direction {
    case sending
    case receiving
}

protocol IdentityKeyStore: AnyObject {
    func identityKeyPair(context: UnsafeMutableRawPointer?) throws -> IdentityKeyPair
    func localRegistrationId(context: UnsafeMutableRawPointer?) throws -> UInt32
    func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws -> Bool
    func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, direction: Direction, context: UnsafeMutableRawPointer?) throws -> Bool
    func identity(for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws -> Optional<IdentityKey>
}

protocol PreKeyStore: AnyObject {
    func loadPreKey(id: UInt32, context: UnsafeMutableRawPointer?) throws -> PreKeyRecord
    func storePreKey(_ record: PreKeyRecord, id: UInt32, context: UnsafeMutableRawPointer?) throws
    func removePreKey(id: UInt32, context: UnsafeMutableRawPointer?) throws
}

protocol SignedPreKeyStore: AnyObject {
    func loadSignedPreKey(id: UInt32, context: UnsafeMutableRawPointer?) throws -> SignedPreKeyRecord
    func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context: UnsafeMutableRawPointer?) throws
}

protocol SessionStore: AnyObject {
    func loadSession(for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws -> SessionRecord?
    func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws
}

protocol SenderKeyStore: AnyObject {
    func storeSenderKey(name: SenderKeyName, record: SenderKeyRecord, context: UnsafeMutableRawPointer?) throws
    func loadSenderKey(name: SenderKeyName, context: UnsafeMutableRawPointer?) throws -> SenderKeyRecord?
}
