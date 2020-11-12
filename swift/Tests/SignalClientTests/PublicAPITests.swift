//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest
import SignalClient

class PublicAPITests: XCTestCase {
    func testHkdfSimple() {
        let ikm: [UInt8] = [
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ]
        let info: [UInt8] = []
        let salt: [UInt8] = []
        let okm: [UInt8] = [0x8d, 0xa4, 0xe7, 0x75]

        let version = UInt32(3)
        let derived = try! hkdf(outputLength: okm.count,
                                version: version,
                                inputKeyMaterial: ikm,
                                salt: salt,
                                info: info)
        XCTAssertEqual(derived, okm)

        XCTAssertThrowsError(try hkdf(outputLength: okm.count,
                                      version: 19,
                                      inputKeyMaterial: ikm,
                                      salt: salt,
                                      info: info))
    }

    func testHkdfUsingRFCExample() {
        // https://tools.ietf.org/html/rfc5869 A.2
        let ikm: [UInt8] = Array(0...0x4f)
        let salt: [UInt8] = Array(0x60...0xaf)
        let info: [UInt8] = Array(0xb0...0xff)
        let okm: [UInt8] = [0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
                            0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
                            0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
                            0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8, 0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
                            0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87, 0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
                            0x1d, 0x87]

        let version = UInt32(3)
        let derived = try! hkdf(outputLength: okm.count,
                                version: version,
                                inputKeyMaterial: ikm,
                                salt: salt,
                                info: info)
        XCTAssertEqual(derived, okm)
    }

    func testAddress() {
        let addr = try! ProtocolAddress(name: "addr1", deviceId: 5)
        XCTAssertEqual(addr.name, "addr1")
        XCTAssertEqual(addr.deviceId, 5)
    }

    func testPkOperations() {
        let sk = try! PrivateKey.generate()
        let sk_bytes = try! sk.serialize()

        let pk = try! sk.publicKey()
        let pk_bytes = try! pk.serialize()
        XCTAssertEqual(pk_bytes[0], 0x05) // DJB
        XCTAssertEqual(pk_bytes.count, 33)

        let pk_raw = try! pk.keyBytes()
        XCTAssertEqual(pk_raw.count, 32)
        XCTAssertEqual(pk_raw[0...31], pk_bytes[1...32])

        let sk_reloaded = try! PrivateKey(sk_bytes)
        let pk_reloaded = try! sk_reloaded.publicKey()

        XCTAssertEqual(pk, pk_reloaded)

        XCTAssertEqual(try! pk.serialize(), try! pk_reloaded.serialize())

        var message: [UInt8] = [1, 2, 3]
        var signature = try! sk.generateSignature(message: message)

        XCTAssertEqual(try! pk.verifySignature(message: message, signature: signature), true)

        signature[5] ^= 1
        XCTAssertEqual(try! pk.verifySignature(message: message, signature: signature), false)
        signature[5] ^= 1
        XCTAssertEqual(try! pk.verifySignature(message: message, signature: signature), true)
        message[1] ^= 1
        XCTAssertEqual(try! pk.verifySignature(message: message, signature: signature), false)
        message[1] ^= 1
        XCTAssertEqual(try! pk.verifySignature(message: message, signature: signature), true)

        let sk2 = try! PrivateKey.generate()

        let shared_secret1 = try! sk.keyAgreement(with: sk2.publicKey())
        let shared_secret2 = try! sk2.keyAgreement(with: sk.publicKey())

        XCTAssertEqual(shared_secret1, shared_secret2)
    }

    func testFingerprint() {

        let ALICE_IDENTITY: [UInt8] = [0x05, 0x06, 0x86, 0x3b, 0xc6, 0x6d, 0x02, 0xb4, 0x0d, 0x27, 0xb8, 0xd4, 0x9c, 0xa7, 0xc0, 0x9e, 0x92, 0x39, 0x23, 0x6f, 0x9d, 0x7d, 0x25, 0xd6, 0xfc, 0xca, 0x5c, 0xe1, 0x3c, 0x70, 0x64, 0xd8, 0x68]
        let BOB_IDENTITY: [UInt8] = [0x05, 0xf7, 0x81, 0xb6, 0xfb, 0x32, 0xfe, 0xd9, 0xba, 0x1c, 0xf2, 0xde, 0x97, 0x8d, 0x4d, 0x5d, 0xa2, 0x8d, 0xc3, 0x40, 0x46, 0xae, 0x81, 0x44, 0x02, 0xb5, 0xc0, 0xdb, 0xd9, 0x6f, 0xda, 0x90, 0x7b]

        let VERSION_1                      = 1
        let DISPLAYABLE_FINGERPRINT_V1     = "300354477692869396892869876765458257569162576843440918079131"
        let ALICE_SCANNABLE_FINGERPRINT_V1: [UInt8] = [0x08, 0x01, 0x12, 0x22, 0x0a, 0x20, 0x1e, 0x30, 0x1a, 0x03, 0x53, 0xdc, 0xe3, 0xdb, 0xe7, 0x68, 0x4c, 0xb8, 0x33, 0x6e, 0x85, 0x13, 0x6c, 0xdc, 0x0e, 0xe9, 0x62, 0x19, 0x49, 0x4a, 0xda, 0x30, 0x5d, 0x62, 0xa7, 0xbd, 0x61, 0xdf, 0x1a, 0x22, 0x0a, 0x20, 0xd6, 0x2c, 0xbf, 0x73, 0xa1, 0x15, 0x92, 0x01, 0x5b, 0x6b, 0x9f, 0x16, 0x82, 0xac, 0x30, 0x6f, 0xea, 0x3a, 0xaf, 0x38, 0x85, 0xb8, 0x4d, 0x12, 0xbc, 0xa6, 0x31, 0xe9, 0xd4, 0xfb, 0x3a, 0x4d]
        let BOB_SCANNABLE_FINGERPRINT_V1: [UInt8] = [0x08, 0x01, 0x12, 0x22, 0x0a, 0x20, 0xd6, 0x2c, 0xbf, 0x73, 0xa1, 0x15, 0x92, 0x01, 0x5b, 0x6b, 0x9f, 0x16, 0x82, 0xac, 0x30, 0x6f, 0xea, 0x3a, 0xaf, 0x38, 0x85, 0xb8, 0x4d, 0x12, 0xbc, 0xa6, 0x31, 0xe9, 0xd4, 0xfb, 0x3a, 0x4d, 0x1a, 0x22, 0x0a, 0x20, 0x1e, 0x30, 0x1a, 0x03, 0x53, 0xdc, 0xe3, 0xdb, 0xe7, 0x68, 0x4c, 0xb8, 0x33, 0x6e, 0x85, 0x13, 0x6c, 0xdc, 0x0e, 0xe9, 0x62, 0x19, 0x49, 0x4a, 0xda, 0x30, 0x5d, 0x62, 0xa7, 0xbd, 0x61, 0xdf]

        let VERSION_2                      = 2
        let DISPLAYABLE_FINGERPRINT_V2     = DISPLAYABLE_FINGERPRINT_V1
        let ALICE_SCANNABLE_FINGERPRINT_V2: [UInt8] = [0x08, 0x02, 0x12, 0x22, 0x0a, 0x20, 0x1e, 0x30, 0x1a, 0x03, 0x53, 0xdc, 0xe3, 0xdb, 0xe7, 0x68, 0x4c, 0xb8, 0x33, 0x6e, 0x85, 0x13, 0x6c, 0xdc, 0x0e, 0xe9, 0x62, 0x19, 0x49, 0x4a, 0xda, 0x30, 0x5d, 0x62, 0xa7, 0xbd, 0x61, 0xdf, 0x1a, 0x22, 0x0a, 0x20, 0xd6, 0x2c, 0xbf, 0x73, 0xa1, 0x15, 0x92, 0x01, 0x5b, 0x6b, 0x9f, 0x16, 0x82, 0xac, 0x30, 0x6f, 0xea, 0x3a, 0xaf, 0x38, 0x85, 0xb8, 0x4d, 0x12, 0xbc, 0xa6, 0x31, 0xe9, 0xd4, 0xfb, 0x3a, 0x4d]
        let BOB_SCANNABLE_FINGERPRINT_V2: [UInt8] = [0x08, 0x02, 0x12, 0x22, 0x0a, 0x20, 0xd6, 0x2c, 0xbf, 0x73, 0xa1, 0x15, 0x92, 0x01, 0x5b, 0x6b, 0x9f, 0x16, 0x82, 0xac, 0x30, 0x6f, 0xea, 0x3a, 0xaf, 0x38, 0x85, 0xb8, 0x4d, 0x12, 0xbc, 0xa6, 0x31, 0xe9, 0xd4, 0xfb, 0x3a, 0x4d, 0x1a, 0x22, 0x0a, 0x20, 0x1e, 0x30, 0x1a, 0x03, 0x53, 0xdc, 0xe3, 0xdb, 0xe7, 0x68, 0x4c, 0xb8, 0x33, 0x6e, 0x85, 0x13, 0x6c, 0xdc, 0x0e, 0xe9, 0x62, 0x19, 0x49, 0x4a, 0xda, 0x30, 0x5d, 0x62, 0xa7, 0xbd, 0x61, 0xdf]

        // testVectorsVersion1
        let aliceStableId: [UInt8] = [UInt8]("+14152222222".utf8)
        let bobStableId: [UInt8] = [UInt8]("+14153333333".utf8)

        let aliceIdentityKey = try! PublicKey(ALICE_IDENTITY)
        let bobIdentityKey = try! PublicKey(BOB_IDENTITY)

        let generator = NumericFingerprintGenerator(iterations: 5200)

        let aliceFingerprint = try! generator.create(version: VERSION_1,
                                                     localIdentifier: aliceStableId,
                                                     localKey: aliceIdentityKey,
                                                     remoteIdentifier: bobStableId,
                                                     remoteKey: bobIdentityKey)

        let bobFingerprint = try! generator.create(version: VERSION_1,
                                                   localIdentifier: bobStableId,
                                                   localKey: bobIdentityKey,
                                                   remoteIdentifier: aliceStableId,
                                                   remoteKey: aliceIdentityKey)

        XCTAssertEqual(aliceFingerprint.displayable.formatted, DISPLAYABLE_FINGERPRINT_V1)
        XCTAssertEqual(bobFingerprint.displayable.formatted, DISPLAYABLE_FINGERPRINT_V1)

        XCTAssertEqual(aliceFingerprint.scannable.encoding, ALICE_SCANNABLE_FINGERPRINT_V1)
        XCTAssertEqual(bobFingerprint.scannable.encoding, BOB_SCANNABLE_FINGERPRINT_V1)

        // testVectorsVersion2

        let aliceFingerprint2 = try! generator.create(version: VERSION_2,
                                                      localIdentifier: aliceStableId,
                                                      localKey: aliceIdentityKey,
                                                      remoteIdentifier: bobStableId,
                                                      remoteKey: bobIdentityKey)

        let bobFingerprint2 = try! generator.create(version: VERSION_2,
                                                    localIdentifier: bobStableId,
                                                    localKey: bobIdentityKey,
                                                    remoteIdentifier: aliceStableId,
                                                    remoteKey: aliceIdentityKey)

        XCTAssertEqual(aliceFingerprint2.displayable.formatted, DISPLAYABLE_FINGERPRINT_V2)
        XCTAssertEqual(bobFingerprint2.displayable.formatted, DISPLAYABLE_FINGERPRINT_V2)

        XCTAssertEqual(aliceFingerprint2.scannable.encoding, ALICE_SCANNABLE_FINGERPRINT_V2)
        XCTAssertEqual(bobFingerprint2.scannable.encoding, BOB_SCANNABLE_FINGERPRINT_V2)

        // testMismatchingFingerprints

        let mitmIdentityKey = try! PrivateKey.generate().publicKey()

        let aliceFingerprintM = try! generator.create(version: VERSION_1,
                                                      localIdentifier: aliceStableId,
                                                      localKey: aliceIdentityKey,
                                                      remoteIdentifier: bobStableId,
                                                      remoteKey: mitmIdentityKey)

        let bobFingerprintM = try! generator.create(version: VERSION_1,
                                                    localIdentifier: bobStableId,
                                                    localKey: bobIdentityKey,
                                                    remoteIdentifier: aliceStableId,
                                                    remoteKey: aliceIdentityKey)

        XCTAssertNotEqual(aliceFingerprintM.displayable.formatted,
                          bobFingerprintM.displayable.formatted)

        XCTAssertEqual(try! bobFingerprintM.scannable.compare(against: aliceFingerprintM.scannable), false)
        XCTAssertEqual(try! aliceFingerprintM.scannable.compare(against: bobFingerprintM.scannable), false)

        XCTAssertEqual(aliceFingerprintM.displayable.formatted.count, 60)

        // testMismatchingIdentifiers

        let badBobStableId: [UInt8] = [UInt8]("+14153333334".utf8)

        let aliceFingerprintI = try! generator.create(version: VERSION_1,
                                                      localIdentifier: aliceStableId,
                                                      localKey: aliceIdentityKey,
                                                      remoteIdentifier: badBobStableId,
                                                      remoteKey: bobIdentityKey)

        let bobFingerprintI = try! generator.create(version: VERSION_1,
                                                    localIdentifier: bobStableId,
                                                    localKey: bobIdentityKey,
                                                    remoteIdentifier: aliceStableId,
                                                    remoteKey: aliceIdentityKey)

        XCTAssertNotEqual(aliceFingerprintI.displayable.formatted,
                          bobFingerprintI.displayable.formatted)

        XCTAssertEqual(try! bobFingerprintI.scannable.compare(against: aliceFingerprintI.scannable), false)
        XCTAssertEqual(try! aliceFingerprintI.scannable.compare(against: bobFingerprintI.scannable), false)
    }

    func testGroupCipher() {

        let sender = try! ProtocolAddress(name: "+14159999111", deviceId: 4)
        let group_id = try! SenderKeyName(groupName: "summer camp", sender: sender)

        let a_store = try! InMemorySignalProtocolStore()

        let skdm = try! SenderKeyDistributionMessage(name: group_id, store: a_store, context: nil)

        let skdm_bits = try! skdm.serialize()

        let skdm_r = try! SenderKeyDistributionMessage(bytes: skdm_bits)

        let a_ctext = try! groupEncrypt(groupId: group_id, message: [1, 2, 3], store: a_store, context: nil)

        let b_store = try! InMemorySignalProtocolStore()
        try! processSenderKeyDistributionMessage(sender: group_id,
                                                 message: skdm_r,
                                                 store: b_store,
                                                 context: nil)
        let b_ptext = try! groupDecrypt(groupId: group_id, message: a_ctext, store: b_store, context: nil)

        XCTAssertEqual(b_ptext, [1, 2, 3])
    }

    func testSessionCipher() {
        let alice_address = try! ProtocolAddress(name: "+14151111111", deviceId: 1)
        let bob_address = try! ProtocolAddress(name: "+14151111112", deviceId: 1)

        let alice_store = try! InMemorySignalProtocolStore()
        let bob_store = try! InMemorySignalProtocolStore()

        let bob_pre_key = try! PrivateKey.generate()
        let bob_signed_pre_key = try! PrivateKey.generate()

        let bob_signed_pre_key_public = try! bob_signed_pre_key.publicKey().serialize()

        let bob_identity_key = try! bob_store.identityKeyPair(context: nil).identityKey
        let bob_signed_pre_key_signature = try! bob_store.identityKeyPair(context: nil).privateKey.generateSignature(message: bob_signed_pre_key_public)

        let prekey_id: UInt32 = 4570
        let signed_prekey_id: UInt32 = 3006

        let bob_bundle = try! PreKeyBundle(registrationId: try! bob_store.localRegistrationId(context: nil),
                                           deviceId: 9,
                                           prekeyId: prekey_id,
                                           prekey: bob_pre_key.publicKey(),
                                           signedPrekeyId: signed_prekey_id,
                                           signedPrekey: try! bob_signed_pre_key.publicKey(),
                                           signedPrekeySignature: bob_signed_pre_key_signature,
                                           identity: bob_identity_key)

        // Alice processes the bundle:
        try! processPreKeyBundle(bob_bundle,
                                 for: bob_address,
                                 sessionStore: alice_store,
                                 identityStore: alice_store,
                                 context: nil)

        XCTAssertEqual(try! alice_store.loadSession(for: bob_address, context: nil)?.remoteRegistrationId(),
                       try! bob_store.localRegistrationId(context: nil))

        // Bob does the same:
        try! bob_store.storePreKey(PreKeyRecord(id: prekey_id, privateKey: bob_pre_key),
                                   id: prekey_id,
                                   context: nil)

        try! bob_store.storeSignedPreKey(SignedPreKeyRecord(
                                           id: signed_prekey_id,
                                           timestamp: 42000,
            privateKey: bob_signed_pre_key,
                                           signature: bob_signed_pre_key_signature
                                         ),
                                         id: signed_prekey_id,
                                         context: nil)

        // Alice sends a message:
        let ptext_a: [UInt8] = [8, 6, 7, 5, 3, 0, 9]

        let ctext_a = try! signalEncrypt(message: ptext_a,
                                         for: bob_address,
                                         sessionStore: alice_store,
                                         identityStore: alice_store,
                                         context: nil)

        XCTAssertEqual(try! ctext_a.messageType(), .preKey)

        let ctext_b = try! PreKeySignalMessage(bytes: try! ctext_a.serialize())

        let ptext_b = try! signalDecryptPreKey(message: ctext_b,
                                               from: alice_address,
                                               sessionStore: bob_store,
                                               identityStore: bob_store,
                                               preKeyStore: bob_store,
                                               signedPreKeyStore: bob_store,
                                               context: nil)

        XCTAssertEqual(ptext_a, ptext_b)

        // Bob replies
        let ptext2_b: [UInt8] = [23]

        let ctext2_b = try! signalEncrypt(message: ptext2_b,
                                          for: alice_address,
                                          sessionStore: bob_store,
                                          identityStore: bob_store,
                                          context: nil)

        XCTAssertEqual(try! ctext2_b.messageType(), .whisper)

        let ctext2_a = try! SignalMessage(bytes: try! ctext2_b.serialize())

        let ptext2_a = try! signalDecrypt(message: ctext2_a,
                                          from: bob_address,
                                          sessionStore: alice_store,
                                          identityStore: alice_store,
                                          context: nil)

        XCTAssertEqual(ptext2_a, ptext2_b)
    }

    static var allTests: [(String, (PublicAPITests) -> () throws -> Void)] {
        return [
            ("testAddreses", testAddress),
            ("testFingerprint", testFingerprint),
            ("testPkOperations", testPkOperations),
            ("testHkdfSimple", testHkdfSimple),
            ("testHkdfUsingRFCExample", testHkdfUsingRFCExample),
            ("testGroupCipher", testGroupCipher),
            ("testSessionCipher", testSessionCipher),
        ]
    }
}
