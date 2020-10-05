import SignalFfi
import Foundation

enum Direction {
    case sending
    case receiving
}

protocol IdentityKeyStore: AnyObject {
    func getIdentityKeyPair(ctx: UnsafeMutableRawPointer?) throws -> IdentityKeyPair
    func getLocalRegistrationId(ctx: UnsafeMutableRawPointer?) throws -> UInt32
    func saveIdentity(address: ProtocolAddress, identity: IdentityKey, ctx: UnsafeMutableRawPointer?) throws -> Bool
    func isTrustedIdentity(address: ProtocolAddress, identity: IdentityKey, direction: Direction, ctx: UnsafeMutableRawPointer?) throws -> Bool
    func getIdentity(address: ProtocolAddress, ctx: UnsafeMutableRawPointer?) throws -> Optional<IdentityKey>
}

protocol PreKeyStore: AnyObject {
    func loadPreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws -> PreKeyRecord
    func storePreKey(id: UInt32, record: PreKeyRecord, ctx: UnsafeMutableRawPointer?) throws
    func removePreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws
}

protocol SignedPreKeyStore: AnyObject {
    func loadSignedPreKey(id: UInt32, ctx: UnsafeMutableRawPointer?) throws -> SignedPreKeyRecord
    func storeSignedPreKey(id: UInt32, record: SignedPreKeyRecord, ctx: UnsafeMutableRawPointer?) throws
}

protocol SessionStore: AnyObject {
    func loadSession(address: ProtocolAddress, ctx: UnsafeMutableRawPointer?) throws -> Optional<SessionRecord>
    func storeSession(address: ProtocolAddress, record: SessionRecord, ctx: UnsafeMutableRawPointer?) throws
}

protocol SenderKeyStore: AnyObject {
    func storeSenderKey(name: SenderKeyName, record: SenderKeyRecord, ctx: UnsafeMutableRawPointer?) throws
    func loadSenderKey(name: SenderKeyName, ctx: UnsafeMutableRawPointer?) throws -> SenderKeyRecord?
}
