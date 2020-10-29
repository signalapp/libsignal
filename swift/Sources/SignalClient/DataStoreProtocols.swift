//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi

public enum Direction {
    case sending
    case receiving
}

public protocol IdentityKeyStore: AnyObject {
    func identityKeyPair(context: UnsafeMutableRawPointer?) throws -> IdentityKeyPair
    func localRegistrationId(context: UnsafeMutableRawPointer?) throws -> UInt32
    func saveIdentity(_ identity: IdentityKey, for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws -> Bool
    func isTrustedIdentity(_ identity: IdentityKey, for address: ProtocolAddress, direction: Direction, context: UnsafeMutableRawPointer?) throws -> Bool
    func identity(for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws -> IdentityKey?
}

public protocol PreKeyStore: AnyObject {
    func loadPreKey(id: UInt32, context: UnsafeMutableRawPointer?) throws -> PreKeyRecord
    func storePreKey(_ record: PreKeyRecord, id: UInt32, context: UnsafeMutableRawPointer?) throws
    func removePreKey(id: UInt32, context: UnsafeMutableRawPointer?) throws
}

public protocol SignedPreKeyStore: AnyObject {
    func loadSignedPreKey(id: UInt32, context: UnsafeMutableRawPointer?) throws -> SignedPreKeyRecord
    func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context: UnsafeMutableRawPointer?) throws
}

public protocol SessionStore: AnyObject {
    func loadSession(for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws -> SessionRecord?
    func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: UnsafeMutableRawPointer?) throws
}

public protocol SenderKeyStore: AnyObject {
    func storeSenderKey(name: SenderKeyName, record: SenderKeyRecord, context: UnsafeMutableRawPointer?) throws
    func loadSenderKey(name: SenderKeyName, context: UnsafeMutableRawPointer?) throws -> SenderKeyRecord?
}
