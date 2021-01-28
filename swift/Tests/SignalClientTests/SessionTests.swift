//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest
import SignalClient

class SessionTests: TestCaseBase {
    fileprivate func initializeSessions(alice_store: InMemorySignalProtocolStore,
                                        bob_store: InMemorySignalProtocolStore,
                                        bob_address: ProtocolAddress) {
        let bob_pre_key = PrivateKey.generate()
        let bob_signed_pre_key = PrivateKey.generate()

        let bob_signed_pre_key_public = bob_signed_pre_key.publicKey.serialize()

        let bob_identity_key = try! bob_store.identityKeyPair(context: NullContext()).identityKey
        let bob_signed_pre_key_signature = try! bob_store.identityKeyPair(context: NullContext()).privateKey.generateSignature(message: bob_signed_pre_key_public)

        let prekey_id: UInt32 = 4570
        let signed_prekey_id: UInt32 = 3006

        let bob_bundle = try! PreKeyBundle(registrationId: bob_store.localRegistrationId(context: NullContext()),
                                           deviceId: 9,
                                           prekeyId: prekey_id,
                                           prekey: bob_pre_key.publicKey,
                                           signedPrekeyId: signed_prekey_id,
                                           signedPrekey: bob_signed_pre_key.publicKey,
                                           signedPrekeySignature: bob_signed_pre_key_signature,
                                           identity: bob_identity_key)

        // Alice processes the bundle:
        try! processPreKeyBundle(bob_bundle,
                                 for: bob_address,
                                 sessionStore: alice_store,
                                 identityStore: alice_store,
                                 context: NullContext())

        XCTAssertEqual(try! alice_store.loadSession(for: bob_address, context: NullContext())?.hasCurrentState, true)
        XCTAssertEqual(try! alice_store.loadSession(for: bob_address, context: NullContext())?.remoteRegistrationId(),
                       try! bob_store.localRegistrationId(context: NullContext()))

        // Bob does the same:
        try! bob_store.storePreKey(PreKeyRecord(id: prekey_id, privateKey: bob_pre_key),
                                   id: prekey_id,
                                   context: NullContext())

        try! bob_store.storeSignedPreKey(
            SignedPreKeyRecord(
                id: signed_prekey_id,
                timestamp: 42000,
                privateKey: bob_signed_pre_key,
                signature: bob_signed_pre_key_signature
            ),
            id: signed_prekey_id,
            context: NullContext())
    }

    func testSessionCipher() {
        let alice_address = try! ProtocolAddress(name: "+14151111111", deviceId: 1)
        let bob_address = try! ProtocolAddress(name: "+14151111112", deviceId: 1)

        let alice_store = InMemorySignalProtocolStore()
        let bob_store = InMemorySignalProtocolStore()

        initializeSessions(alice_store: alice_store, bob_store: bob_store, bob_address: bob_address)

        // Alice sends a message:
        let ptext_a: [UInt8] = [8, 6, 7, 5, 3, 0, 9]

        let ctext_a = try! signalEncrypt(message: ptext_a,
                                         for: bob_address,
                                         sessionStore: alice_store,
                                         identityStore: alice_store,
                                         context: NullContext())

        XCTAssertEqual(ctext_a.messageType, .preKey)

        let ctext_b = try! PreKeySignalMessage(bytes: ctext_a.serialize())

        let ptext_b = try! signalDecryptPreKey(message: ctext_b,
                                               from: alice_address,
                                               sessionStore: bob_store,
                                               identityStore: bob_store,
                                               preKeyStore: bob_store,
                                               signedPreKeyStore: bob_store,
                                               context: NullContext())

        XCTAssertEqual(ptext_a, ptext_b)

        // Bob replies
        let ptext2_b: [UInt8] = [23]

        let ctext2_b = try! signalEncrypt(message: ptext2_b,
                                          for: alice_address,
                                          sessionStore: bob_store,
                                          identityStore: bob_store,
                                          context: NullContext())

        XCTAssertEqual(ctext2_b.messageType, .whisper)

        let ctext2_a = try! SignalMessage(bytes: ctext2_b.serialize())

        let ptext2_a = try! signalDecrypt(message: ctext2_a,
                                          from: bob_address,
                                          sessionStore: alice_store,
                                          identityStore: alice_store,
                                          context: NullContext())

        XCTAssertEqual(ptext2_a, ptext2_b)
    }

    func testSessionCipherWithBadStore() {
        let alice_address = try! ProtocolAddress(name: "+14151111111", deviceId: 1)
        let bob_address = try! ProtocolAddress(name: "+14151111112", deviceId: 1)

        let alice_store = InMemorySignalProtocolStore()
        let bob_store = BadStore()

        initializeSessions(alice_store: alice_store, bob_store: bob_store, bob_address: bob_address)

        // Alice sends a message:
        let ptext_a: [UInt8] = [8, 6, 7, 5, 3, 0, 9]

        let ctext_a = try! signalEncrypt(message: ptext_a,
                                         for: bob_address,
                                         sessionStore: alice_store,
                                         identityStore: alice_store,
                                         context: NullContext())

        XCTAssertEqual(ctext_a.messageType, .preKey)

        let ctext_b = try! PreKeySignalMessage(bytes: ctext_a.serialize())

        XCTAssertThrowsError(try signalDecryptPreKey(message: ctext_b,
                                                     from: alice_address,
                                                     sessionStore: bob_store,
                                                     identityStore: bob_store,
                                                     preKeyStore: bob_store,
                                                     signedPreKeyStore: bob_store,
                                                     context: NullContext()),
                             "should fail to decrypt") { error in
            guard case BadStore.Error.badness = error else {
                XCTFail("wrong error thrown")
                return
            }
        }
    }

    func testSealedSenderSession() throws {
        let alice_address = try! ProtocolAddress(name: "9d0652a3-dcc3-4d11-975f-74d61598733f", deviceId: 1)
        let bob_address = try! ProtocolAddress(name: "6838237D-02F6-4098-B110-698253D15961", deviceId: 1)

        let alice_store = InMemorySignalProtocolStore()
        let bob_store = InMemorySignalProtocolStore()

        initializeSessions(alice_store: alice_store, bob_store: bob_store, bob_address: bob_address)

        let trust_root = IdentityKeyPair.generate()
        let server_keys = IdentityKeyPair.generate()
        let server_cert = try! ServerCertificate(keyId: 1, publicKey: server_keys.publicKey, trustRoot: trust_root.privateKey)
        let sender_addr = try! SealedSenderAddress(e164: "+14151111111",
                                                   uuidString: alice_address.name,
                                                   deviceId: 1)
        let sender_cert = try! SenderCertificate(sender: sender_addr,
                                                 publicKey: alice_store.identityKeyPair(context: NullContext()).publicKey,
                                                 expiration: 31337,
                                                 signerCertificate: server_cert,
                                                 signerKey: server_keys.privateKey)

        let message = Array("2020 vision".utf8)
        let ciphertext = try sealedSenderEncrypt(message: message,
                                                 for: bob_address,
                                                 from: sender_cert,
                                                 sessionStore: alice_store,
                                                 identityStore: alice_store,
                                                 context: NullContext())

        let recipient_addr = try! SealedSenderAddress(e164: nil, uuidString: bob_address.name, deviceId: 1)
        let plaintext = try sealedSenderDecrypt(message: ciphertext,
                                                from: recipient_addr,
                                                trustRoot: trust_root.publicKey,
                                                timestamp: 31335,
                                                sessionStore: bob_store,
                                                identityStore: bob_store,
                                                preKeyStore: bob_store,
                                                signedPreKeyStore: bob_store,
                                                context: NullContext())

        XCTAssertEqual(plaintext.message, message)
        XCTAssertEqual(plaintext.sender, sender_addr)
    }

    func testArchiveSession() throws {
        let bob_address = try! ProtocolAddress(name: "+14151111112", deviceId: 1)

        let alice_store = InMemorySignalProtocolStore()
        let bob_store = InMemorySignalProtocolStore()

        initializeSessions(alice_store: alice_store, bob_store: bob_store, bob_address: bob_address)

        let session: SessionRecord! = try! alice_store.loadSession(for: bob_address, context: NullContext())
        XCTAssertNotNil(session)
        XCTAssertTrue(session.hasCurrentState)
        session.archiveCurrentState()
        XCTAssertFalse(session.hasCurrentState)
        // A redundant archive shouldn't break anything.
        session.archiveCurrentState()
        XCTAssertFalse(session.hasCurrentState)
    }

    static var allTests: [(String, (SessionTests) -> () throws -> Void)] {
        return [
            ("testSessionCipher", testSessionCipher),
            ("testSessionCipherWithBadStore", testSessionCipherWithBadStore),
            ("testSealedSenderSession", testSealedSenderSession),
            ("testArchiveSession", testArchiveSession),
        ]
    }
}
