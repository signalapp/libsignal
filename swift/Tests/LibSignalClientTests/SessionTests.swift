//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest
import LibSignalClient

typealias InitSession = (
    _ aliceStore: InMemorySignalProtocolStore,
    _ bobStore: InMemorySignalProtocolStore,
    _ bobAddress: ProtocolAddress
) -> Void

class SessionTests: TestCaseBase {
    func testSessionCipher() {
        run(initializeSessionsV3)
        run(initializeSessionsV4)

        func run(_ initSessions: InitSession) {
            let alice_address = try! ProtocolAddress(name: "+14151111111", deviceId: 1)
            let bob_address = try! ProtocolAddress(name: "+14151111112", deviceId: 1)

            let alice_store = InMemorySignalProtocolStore()
            let bob_store = InMemorySignalProtocolStore()

            initSessions(alice_store, bob_store, bob_address)

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
                                                   kyberPreKeyStore: bob_store,
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
    }

    func testSessionCipherWithBadStore() {
        run(initializeSessionsV3)
        run(initializeSessionsV4)

        func run(_ initSession: InitSession) {
            let alice_address = try! ProtocolAddress(name: "+14151111111", deviceId: 1)
            let bob_address = try! ProtocolAddress(name: "+14151111112", deviceId: 1)

            let alice_store = InMemorySignalProtocolStore()
            let bob_store = BadStore()

            initializeSessionsV3(alice_store: alice_store, bob_store: bob_store, bob_address: bob_address)

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
                                                         kyberPreKeyStore: bob_store,
                                                         context: NullContext()),
                                 "should fail to decrypt") { error in
                guard case BadStore.Error.badness = error else {
                    XCTFail("wrong error thrown: \(error)")
                    return
                }
            }
        }
    }

    func testSealedSenderSession() throws {
        let alice_address = try! ProtocolAddress(name: "9d0652a3-dcc3-4d11-975f-74d61598733f", deviceId: 1)
        let bob_address = try! ProtocolAddress(name: "6838237D-02F6-4098-B110-698253D15961", deviceId: 1)

        let alice_store = InMemorySignalProtocolStore()
        let bob_store = InMemorySignalProtocolStore()

        initializeSessionsV3(alice_store: alice_store, bob_store: bob_store, bob_address: bob_address)

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

        let innerMessage = try signalEncrypt(message: [],
                                             for: bob_address,
                                             sessionStore: alice_store,
                                             identityStore: alice_store,
                                             context: NullContext())

        for hint in [UnidentifiedSenderMessageContent.ContentHint(rawValue: 200), .default, .resendable, .implicit] {
            let content = try UnidentifiedSenderMessageContent(innerMessage,
                                                               from: sender_cert,
                                                               contentHint: hint,
                                                               groupId: [])
            let ciphertext = try sealedSenderEncrypt(content,
                                                     for: bob_address,
                                                     identityStore: alice_store,
                                                     context: NullContext())

            let decryptedContent = try UnidentifiedSenderMessageContent(message: ciphertext,
                                                                        identityStore: bob_store,
                                                                        context: NullContext())
            XCTAssertEqual(decryptedContent.contentHint, hint)
        }
    }

    func testArchiveSession() throws {
        let bob_address = try! ProtocolAddress(name: "+14151111112", deviceId: 1)

        let alice_store = InMemorySignalProtocolStore()
        let bob_store = InMemorySignalProtocolStore()

        initializeSessionsV3(alice_store: alice_store, bob_store: bob_store, bob_address: bob_address)

        let session: SessionRecord! = try! alice_store.loadSession(for: bob_address, context: NullContext())
        XCTAssertNotNil(session)
        XCTAssertTrue(session.hasCurrentState)
        XCTAssertFalse(try! session.currentRatchetKeyMatches(IdentityKeyPair.generate().publicKey))
        session.archiveCurrentState()
        XCTAssertFalse(session.hasCurrentState)
        XCTAssertFalse(try! session.currentRatchetKeyMatches(IdentityKeyPair.generate().publicKey))
        // A redundant archive shouldn't break anything.
        session.archiveCurrentState()
        XCTAssertFalse(session.hasCurrentState)
    }

    func testSealedSenderGroupCipher() throws {
        let alice_address = try! ProtocolAddress(name: "9d0652a3-dcc3-4d11-975f-74d61598733f", deviceId: 1)
        let bob_address = try! ProtocolAddress(name: "6838237D-02F6-4098-B110-698253D15961", deviceId: 1)

        let alice_store = InMemorySignalProtocolStore()
        let bob_store = InMemorySignalProtocolStore()

        initializeSessionsV3(alice_store: alice_store, bob_store: bob_store, bob_address: bob_address)

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

        let distribution_id = UUID(uuidString: "d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")!

        let skdm = try! SenderKeyDistributionMessage(from: alice_address,
                                                     distributionId: distribution_id,
                                                     store: alice_store,
                                                     context: NullContext())

        let skdm_bits = skdm.serialize()

        let skdm_r = try! SenderKeyDistributionMessage(bytes: skdm_bits)

        try! processSenderKeyDistributionMessage(skdm_r,
                                                 from: alice_address,
                                                 store: bob_store,
                                                 context: NullContext())

        let a_message = try! groupEncrypt([1, 2, 3],
                                          from: alice_address,
                                          distributionId: distribution_id,
                                          store: alice_store,
                                          context: NullContext())

        let a_usmc = try! UnidentifiedSenderMessageContent(a_message,
                                                           from: sender_cert,
                                                           contentHint: .default,
                                                           groupId: [42])

        let a_ctext = try! sealedSenderMultiRecipientEncrypt(a_usmc,
                                                             for: [bob_address],
                                                             identityStore: alice_store,
                                                             sessionStore: alice_store,
                                                             context: NullContext())

        let b_ctext = try! sealedSenderMultiRecipientMessageForSingleRecipient(a_ctext)

        let b_usmc = try! UnidentifiedSenderMessageContent(message: b_ctext,
                                                           identityStore: bob_store,
                                                           context: NullContext())

        XCTAssertEqual(b_usmc.groupId, a_usmc.groupId)

        let b_ptext = try! groupDecrypt(b_usmc.contents,
                                        from: alice_address,
                                        store: bob_store,
                                        context: NullContext())

        XCTAssertEqual(b_ptext, [1, 2, 3])
    }

    func testSealedSenderGroupCipherWithBadRegistrationId() throws {
        let alice_address = try! ProtocolAddress(name: "9d0652a3-dcc3-4d11-975f-74d61598733f", deviceId: 1)
        let bob_address = try! ProtocolAddress(name: "6838237D-02F6-4098-B110-698253D15961", deviceId: 1)

        let alice_store = InMemorySignalProtocolStore()
        let bob_store = InMemorySignalProtocolStore(identity: IdentityKeyPair.generate(), registrationId: 0x4000)

        initializeSessionsV3(alice_store: alice_store, bob_store: bob_store, bob_address: bob_address)

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

        let distribution_id = UUID(uuidString: "d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")!

        _ = try! SenderKeyDistributionMessage(from: alice_address,
                                              distributionId: distribution_id,
                                              store: alice_store,
                                              context: NullContext())

        let a_message = try! groupEncrypt([1, 2, 3],
                                          from: alice_address,
                                          distributionId: distribution_id,
                                          store: alice_store,
                                          context: NullContext())

        let a_usmc = try! UnidentifiedSenderMessageContent(a_message,
                                                           from: sender_cert,
                                                           contentHint: .default,
                                                           groupId: [42])

        do {
            _ = try sealedSenderMultiRecipientEncrypt(a_usmc,
                                                      for: [bob_address],
                                                      identityStore: alice_store,
                                                      sessionStore: alice_store,
                                                      context: NullContext())
            XCTFail("should have thrown")
        } catch SignalError.invalidRegistrationId(address: let address, message: _) {
            XCTAssertEqual(address, bob_address)
        }
    }

    func testDecryptionErrorMessage() throws {
        let alice_address = try! ProtocolAddress(name: "9d0652a3-dcc3-4d11-975f-74d61598733f", deviceId: 1)
        let bob_address = try! ProtocolAddress(name: "6838237D-02F6-4098-B110-698253D15961", deviceId: 1)

        let alice_store = InMemorySignalProtocolStore()
        let bob_store = InMemorySignalProtocolStore()

        // Notice the reverse initialization. Bob will send the first message to Alice in this example.
        initializeSessionsV3(alice_store: bob_store, bob_store: alice_store, bob_address: alice_address)

        let bob_first_message = try signalEncrypt(message: Array("swim camp".utf8),
                                                  for: alice_address,
                                                  sessionStore: bob_store,
                                                  identityStore: bob_store,
                                                  context: NullContext()).serialize()
        _ = try signalDecryptPreKey(message: PreKeySignalMessage(bytes: bob_first_message),
                                    from: bob_address,
                                    sessionStore: alice_store,
                                    identityStore: alice_store,
                                    preKeyStore: alice_store,
                                    signedPreKeyStore: alice_store,
                                    kyberPreKeyStore: bob_store,
                                    context: NullContext())

        let bob_message = try signalEncrypt(message: Array("space camp".utf8),
                                            for: alice_address,
                                            sessionStore: bob_store,
                                            identityStore: bob_store,
                                            context: NullContext())
        let error_message = try DecryptionErrorMessage(originalMessageBytes: bob_message.serialize(),
                                                       type: bob_message.messageType,
                                                       timestamp: 408,
                                                       originalSenderDeviceId: bob_address.deviceId)

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

        let error_message_usmc = try UnidentifiedSenderMessageContent(
            CiphertextMessage(PlaintextContent(error_message)),
            from: sender_cert,
            contentHint: .implicit,
            groupId: [])
        let ciphertext = try sealedSenderEncrypt(error_message_usmc,
                                                 for: bob_address,
                                                 identityStore: alice_store,
                                                 context: NullContext())

        let bob_usmc = try UnidentifiedSenderMessageContent(message: ciphertext,
                                                            identityStore: bob_store,
                                                            context: NullContext())
        XCTAssertEqual(bob_usmc.messageType, .plaintext)
        let bob_content = try PlaintextContent(bytes: bob_usmc.contents)
        let bob_error_message = try DecryptionErrorMessage.extractFromSerializedContent(bob_content.body)
        XCTAssertEqual(bob_error_message.timestamp, 408)
        XCTAssertEqual(bob_error_message.deviceId, bob_address.deviceId)

        let bob_session_with_alice = try XCTUnwrap(bob_store.loadSession(for: alice_address, context: NullContext()))
        XCTAssert(try bob_session_with_alice.currentRatchetKeyMatches(XCTUnwrap(bob_error_message.ratchetKey)))
    }
}

private func initializeSessionsV3(
    alice_store: InMemorySignalProtocolStore,
    bob_store: InMemorySignalProtocolStore,
    bob_address: ProtocolAddress
) {
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

private func initializeSessionsV4(
    alice_store: InMemorySignalProtocolStore,
    bob_store: InMemorySignalProtocolStore,
    bob_address: ProtocolAddress
) {
    let bob_pre_key = PrivateKey.generate()
    let bob_signed_pre_key = PrivateKey.generate()
    let bob_kyber_pre_key = KEMKeyPair.generate()

    let bob_signed_pre_key_public = bob_signed_pre_key.publicKey.serialize()
    let bob_kyber_pre_key_public = bob_kyber_pre_key.publicKey.serialize()

    let bob_identity_key_pair = try! bob_store.identityKeyPair(context: NullContext())
    let bob_identity_key = bob_identity_key_pair.identityKey
    let bob_signed_pre_key_signature = bob_identity_key_pair.privateKey.generateSignature(message: bob_signed_pre_key_public)
    let bob_kyber_pre_key_signature = bob_identity_key_pair.privateKey.generateSignature(message: bob_kyber_pre_key_public)

    let prekey_id: UInt32 = 4570
    let signed_prekey_id: UInt32 = 3006
    let kyber_pre_key_id: UInt32 = 8888

    let bob_bundle = try! PreKeyBundle(registrationId: bob_store.localRegistrationId(context: NullContext()),
                                       deviceId: 9,
                                       prekeyId: prekey_id,
                                       prekey: bob_pre_key.publicKey,
                                       signedPrekeyId: signed_prekey_id,
                                       signedPrekey: bob_signed_pre_key.publicKey,
                                       signedPrekeySignature: bob_signed_pre_key_signature,
                                       identity: bob_identity_key,
                                       kyberPrekeyId: kyber_pre_key_id,
                                       kyberPrekey: bob_kyber_pre_key.publicKey,
                                       kyberPrekeySignature: bob_kyber_pre_key_signature)
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
    try! bob_store.storeKyberPreKey(
        KyberPreKeyRecord(
            id: kyber_pre_key_id,
            timestamp: 42000,
            keyPair: bob_kyber_pre_key,
            signature: bob_kyber_pre_key_signature
        ),
        id: kyber_pre_key_id,
        context: NullContext()
        )
}
