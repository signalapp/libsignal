import SignalFfi
import Foundation

enum Direction {
    case Sending
    case Receiving
}

protocol IdentityKeyStore {
    func getIdentityKeyPair(ctx: UnsafeMutableRawPointer?) throws -> IdentityKeyPair
    func getLocalRegistrationId(ctx: UnsafeMutableRawPointer?) throws -> UInt32
    mutating func saveIdentity(address: ProtocolAddress, identity: IdentityKey, ctx: UnsafeMutableRawPointer?) throws -> Bool
    func isTrustedIdentity(address: ProtocolAddress, identity: IdentityKey, direction: Direction, ctx: UnsafeMutableRawPointer?) throws -> Bool
    func getIdentity(address: ProtocolAddress, ctx: UnsafeMutableRawPointer?) throws -> Optional<IdentityKey>
}

protocol PreKeyStore {
    func getPreKey(prekeyId: UInt32, ctx: UnsafeMutableRawPointer?) throws -> PreKeyRecord
    mutating func savePreKey(prekeyId: UInt32, record: PreKeyRecord, ctx: UnsafeMutableRawPointer?) throws
    func removePreKey(prekeyId: UInt32, ctx: UnsafeMutableRawPointer?) throws
}

protocol SignedPreKeyStore {
    func getSignedPreKey(signedPrekeyId: UInt32, ctx: UnsafeMutableRawPointer?) throws -> SignedPreKeyRecord
    mutating func saveSignedPreKey(signedPrekeyId: UInt32, record: SignedPreKeyRecord, ctx: UnsafeMutableRawPointer?) throws
}

protocol SessionStore {
    func loadSession(address: ProtocolAddress, ctx: UnsafeMutableRawPointer?) throws -> Optional<SessionRecord>
    mutating func storeSession(address: ProtocolAddress, record: SessionRecord, ctx: UnsafeMutableRawPointer?) throws
}

protocol SenderKeyStore {
    mutating func saveSenderKey(name: SenderKeyName, record: SenderKeyRecord, ctx: UnsafeMutableRawPointer?) throws
    func loadSenderKey(name: SenderKeyName, ctx: UnsafeMutableRawPointer?) throws -> SenderKeyRecord?
}
