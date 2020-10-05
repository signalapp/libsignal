import XCTest
@testable import SwiftSignal

class SwiftSignalTests: XCTestCase {
    func testHkdf() {

        let ikm : [UInt8] = [
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
            0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        ]
        let info : [UInt8] = []
        let salt : [UInt8] = []
        let okm : [UInt8] = [0x8d, 0xa4, 0xe7, 0x75]

        let output_length = UInt32(okm.count)
        let version = UInt32(3)
        let derived = try! hkdf(output_length: output_length,
                                version: version,
                                input_key_material: ikm,
                                salt: salt,
                                info: info)
        XCTAssertEqual(derived, okm)

        XCTAssertThrowsError(try hkdf(output_length: output_length,
                                  version: 19,
                                  input_key_material: ikm,
                                  salt: salt,
                                  info: info))
    }

    func testAddress() {
        let addr = try! ProtocolAddress(name: "addr1", device_id: 5)
        XCTAssertEqual(addr.name, "addr1")
        XCTAssertEqual(addr.deviceId, 5)
    }

    func testPkOperations() {
        let sk = try! PrivateKey.generate()

        let sk_bytes = try! sk.serialize()
        let pk = try! sk.getPublicKey()

        let sk_reloaded = try! PrivateKey(sk_bytes)
        let pk_reloaded = try! sk_reloaded.getPublicKey()

        XCTAssertEqual(pk, pk_reloaded)

        XCTAssertEqual(try! pk.serialize(), try! pk_reloaded.serialize())

        var message : [UInt8] = [1, 2, 3]
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

        let shared_secret1 = try! sk.keyAgreement(other_key: sk2.getPublicKey())
        let shared_secret2 = try! sk2.keyAgreement(other_key: sk.getPublicKey())

        XCTAssertEqual(shared_secret1, shared_secret2)
    }

    func testFingerprint() {

        let ALICE_IDENTITY : [UInt8] = [0x05, 0x06, 0x86, 0x3b, 0xc6, 0x6d, 0x02, 0xb4, 0x0d, 0x27, 0xb8, 0xd4, 0x9c, 0xa7, 0xc0, 0x9e, 0x92, 0x39, 0x23, 0x6f, 0x9d, 0x7d, 0x25, 0xd6, 0xfc, 0xca, 0x5c, 0xe1, 0x3c, 0x70, 0x64, 0xd8, 0x68]
        let BOB_IDENTITY : [UInt8] = [0x05, 0xf7, 0x81, 0xb6, 0xfb, 0x32, 0xfe, 0xd9, 0xba, 0x1c, 0xf2, 0xde, 0x97, 0x8d, 0x4d, 0x5d, 0xa2, 0x8d, 0xc3, 0x40, 0x46, 0xae, 0x81, 0x44, 0x02, 0xb5, 0xc0, 0xdb, 0xd9, 0x6f, 0xda, 0x90, 0x7b]

        let VERSION_1                      = 1
        let DISPLAYABLE_FINGERPRINT_V1     = "300354477692869396892869876765458257569162576843440918079131"
        let ALICE_SCANNABLE_FINGERPRINT_V1 : [UInt8] = [0x08, 0x01, 0x12, 0x22, 0x0a, 0x20, 0x1e, 0x30, 0x1a, 0x03, 0x53, 0xdc, 0xe3, 0xdb, 0xe7, 0x68, 0x4c, 0xb8, 0x33, 0x6e, 0x85, 0x13, 0x6c, 0xdc, 0x0e, 0xe9, 0x62, 0x19, 0x49, 0x4a, 0xda, 0x30, 0x5d, 0x62, 0xa7, 0xbd, 0x61, 0xdf, 0x1a, 0x22, 0x0a, 0x20, 0xd6, 0x2c, 0xbf, 0x73, 0xa1, 0x15, 0x92, 0x01, 0x5b, 0x6b, 0x9f, 0x16, 0x82, 0xac, 0x30, 0x6f, 0xea, 0x3a, 0xaf, 0x38, 0x85, 0xb8, 0x4d, 0x12, 0xbc, 0xa6, 0x31, 0xe9, 0xd4, 0xfb, 0x3a, 0x4d]
        let BOB_SCANNABLE_FINGERPRINT_V1 : [UInt8] = [0x08, 0x01, 0x12, 0x22, 0x0a, 0x20, 0xd6, 0x2c, 0xbf, 0x73, 0xa1, 0x15, 0x92, 0x01, 0x5b, 0x6b, 0x9f, 0x16, 0x82, 0xac, 0x30, 0x6f, 0xea, 0x3a, 0xaf, 0x38, 0x85, 0xb8, 0x4d, 0x12, 0xbc, 0xa6, 0x31, 0xe9, 0xd4, 0xfb, 0x3a, 0x4d, 0x1a, 0x22, 0x0a, 0x20, 0x1e, 0x30, 0x1a, 0x03, 0x53, 0xdc, 0xe3, 0xdb, 0xe7, 0x68, 0x4c, 0xb8, 0x33, 0x6e, 0x85, 0x13, 0x6c, 0xdc, 0x0e, 0xe9, 0x62, 0x19, 0x49, 0x4a, 0xda, 0x30, 0x5d, 0x62, 0xa7, 0xbd, 0x61, 0xdf]

        let VERSION_2                      = 2
        let DISPLAYABLE_FINGERPRINT_V2     = DISPLAYABLE_FINGERPRINT_V1
        let ALICE_SCANNABLE_FINGERPRINT_V2: [UInt8] = [0x08, 0x02, 0x12, 0x22, 0x0a, 0x20, 0x1e, 0x30, 0x1a, 0x03, 0x53, 0xdc, 0xe3, 0xdb, 0xe7, 0x68, 0x4c, 0xb8, 0x33, 0x6e, 0x85, 0x13, 0x6c, 0xdc, 0x0e, 0xe9, 0x62, 0x19, 0x49, 0x4a, 0xda, 0x30, 0x5d, 0x62, 0xa7, 0xbd, 0x61, 0xdf, 0x1a, 0x22, 0x0a, 0x20, 0xd6, 0x2c, 0xbf, 0x73, 0xa1, 0x15, 0x92, 0x01, 0x5b, 0x6b, 0x9f, 0x16, 0x82, 0xac, 0x30, 0x6f, 0xea, 0x3a, 0xaf, 0x38, 0x85, 0xb8, 0x4d, 0x12, 0xbc, 0xa6, 0x31, 0xe9, 0xd4, 0xfb, 0x3a, 0x4d]
        let BOB_SCANNABLE_FINGERPRINT_V2  : [UInt8] = [0x08, 0x02, 0x12, 0x22, 0x0a, 0x20, 0xd6, 0x2c, 0xbf, 0x73, 0xa1, 0x15, 0x92, 0x01, 0x5b, 0x6b, 0x9f, 0x16, 0x82, 0xac, 0x30, 0x6f, 0xea, 0x3a, 0xaf, 0x38, 0x85, 0xb8, 0x4d, 0x12, 0xbc, 0xa6, 0x31, 0xe9, 0xd4, 0xfb, 0x3a, 0x4d, 0x1a, 0x22, 0x0a, 0x20, 0x1e, 0x30, 0x1a, 0x03, 0x53, 0xdc, 0xe3, 0xdb, 0xe7, 0x68, 0x4c, 0xb8, 0x33, 0x6e, 0x85, 0x13, 0x6c, 0xdc, 0x0e, 0xe9, 0x62, 0x19, 0x49, 0x4a, 0xda, 0x30, 0x5d, 0x62, 0xa7, 0xbd, 0x61, 0xdf]

        // testVectorsVersion1
        let aliceStableId : [UInt8] = [UInt8]("+14152222222".utf8)
        let bobStableId : [UInt8] = [UInt8]("+14153333333".utf8)

        let aliceIdentityKey = try! PublicKey(ALICE_IDENTITY)
        let bobIdentityKey = try! PublicKey(BOB_IDENTITY)

        let generator = NumericFingerprintGenerator(iterations: 5200)

        let aliceFingerprint = try! generator.createFor(version: VERSION_1,
                                                        local_identifier: aliceStableId,
                                                        local_key: aliceIdentityKey,
                                                        remote_identifier: bobStableId,
                                                        remote_key: bobIdentityKey)

        let bobFingerprint = try! generator.createFor(version: VERSION_1,
                                                      local_identifier: bobStableId,
                                                      local_key: bobIdentityKey,
                                                      remote_identifier: aliceStableId,
                                                      remote_key: aliceIdentityKey)

        XCTAssertEqual(aliceFingerprint.displayable.formatted, DISPLAYABLE_FINGERPRINT_V1)
        XCTAssertEqual(bobFingerprint.displayable.formatted, DISPLAYABLE_FINGERPRINT_V1)

        XCTAssertEqual(aliceFingerprint.scannable.encoding, ALICE_SCANNABLE_FINGERPRINT_V1)
        XCTAssertEqual(bobFingerprint.scannable.encoding, BOB_SCANNABLE_FINGERPRINT_V1)

        // testVectorsVersion2

        let aliceFingerprint2 = try! generator.createFor(version: VERSION_2,
                                                        local_identifier: aliceStableId,
                                                        local_key: aliceIdentityKey,
                                                        remote_identifier: bobStableId,
                                                        remote_key: bobIdentityKey)

        let bobFingerprint2 = try! generator.createFor(version: VERSION_2,
                                                      local_identifier: bobStableId,
                                                      local_key: bobIdentityKey,
                                                      remote_identifier: aliceStableId,
                                                      remote_key: aliceIdentityKey)

        XCTAssertEqual(aliceFingerprint2.displayable.formatted, DISPLAYABLE_FINGERPRINT_V2)
        XCTAssertEqual(bobFingerprint2.displayable.formatted, DISPLAYABLE_FINGERPRINT_V2)

        XCTAssertEqual(aliceFingerprint2.scannable.encoding, ALICE_SCANNABLE_FINGERPRINT_V2)
        XCTAssertEqual(bobFingerprint2.scannable.encoding, BOB_SCANNABLE_FINGERPRINT_V2)

        // testMismatchingFingerprints

        let mitmIdentityKey = try! PrivateKey.generate().getPublicKey()

        let aliceFingerprintM = try! generator.createFor(version: VERSION_1,
                                                        local_identifier: aliceStableId,
                                                        local_key: aliceIdentityKey,
                                                        remote_identifier: bobStableId,
                                                        remote_key: mitmIdentityKey)

        let bobFingerprintM = try! generator.createFor(version: VERSION_1,
                                                      local_identifier: bobStableId,
                                                      local_key: bobIdentityKey,
                                                      remote_identifier: aliceStableId,
                                                      remote_key: aliceIdentityKey)

        XCTAssertNotEqual(aliceFingerprintM.displayable.formatted,
                          bobFingerprintM.displayable.formatted)

        XCTAssertEqual(try! bobFingerprintM.scannable.compareWith(other: aliceFingerprintM.scannable), false)
        XCTAssertEqual(try! aliceFingerprintM.scannable.compareWith(other: bobFingerprintM.scannable), false)

        XCTAssertEqual(aliceFingerprintM.displayable.formatted.count, 60)

        // testMismatchingIdentifiers

        let badBobStableId : [UInt8] = [UInt8]("+14153333334".utf8)

        let aliceFingerprintI = try! generator.createFor(version: VERSION_1,
                                                        local_identifier: aliceStableId,
                                                        local_key: aliceIdentityKey,
                                                        remote_identifier: badBobStableId,
                                                        remote_key: bobIdentityKey)

        let bobFingerprintI = try! generator.createFor(version: VERSION_1,
                                                      local_identifier: bobStableId,
                                                      local_key: bobIdentityKey,
                                                      remote_identifier: aliceStableId,
                                                      remote_key: aliceIdentityKey)

        XCTAssertNotEqual(aliceFingerprintI.displayable.formatted,
                          bobFingerprintI.displayable.formatted)

        XCTAssertEqual(try! bobFingerprintI.scannable.compareWith(other: aliceFingerprintI.scannable), false)
        XCTAssertEqual(try! aliceFingerprintI.scannable.compareWith(other: bobFingerprintI.scannable), false)
    }

    func testGroupCipher() {

        let sender = try! ProtocolAddress(name: "+14159999111", device_id: 4)
        let group_id = try! SenderKeyName(group_name: "summer camp", sender: sender)

        let a_store = try! InMemorySignalProtocolStore()

        let skdm = try! SenderKeyDistributionMessage(name: group_id, store: a_store, ctx: nil)

        let skdm_bits = try! skdm.serialize()

        let skdm_r = try! SenderKeyDistributionMessage(bytes: skdm_bits)

        let a_ctext = try! GroupEncrypt(group_id: group_id, message: [1,2,3], store: a_store, ctx: nil)

        let b_store = try! InMemorySignalProtocolStore()
        try! ProcessSenderKeyDistributionMessage(sender_name: group_id,
                                                 msg: skdm_r,
                                                 store: b_store,
                                                 ctx: nil)
        let b_ptext = try! GroupDecrypt(group_id: group_id, message: a_ctext, store: b_store, ctx: nil)

        XCTAssertEqual(b_ptext, [1,2,3])
    }

    func testSessionCipher() {
        let alice_address = try! ProtocolAddress(name: "+14151111111", device_id: 1)
        let bob_address = try! ProtocolAddress(name: "+14151111112", device_id: 1)

        let alice_store = try! InMemorySignalProtocolStore()
        let bob_store = try! InMemorySignalProtocolStore()

        let bob_pre_key = try! PrivateKey.generate()
        let bob_signed_pre_key = try! PrivateKey.generate()

        let bob_signed_pre_key_public = try! bob_signed_pre_key.getPublicKey().serialize()

        let bob_identity_key = try! bob_store.getIdentityKeyPair(ctx: nil).identityKey();
        let bob_signed_pre_key_signature = try! bob_store.getIdentityKeyPair(ctx: nil).privateKey().generateSignature(message: bob_signed_pre_key_public)

        let prekey_id : UInt32 = 4570;
        let signed_prekey_id : UInt32 = 3006;

        let bob_bundle = try! PreKeyBundle(registration_id: try! bob_store.getLocalRegistrationId(ctx: nil),
                                           device_id: 9,
                                           prekey_id: prekey_id,
                                           prekey: bob_pre_key.getPublicKey(),
                                           signed_prekey_id: signed_prekey_id,
                                           signed_prekey: try! bob_signed_pre_key.getPublicKey(),
                                           signed_prekey_signature: bob_signed_pre_key_signature,
                                           identity_key: bob_identity_key)

        // Alice processes the bundle:
        try! ProcessPreKeyBundle(bundle: bob_bundle,
                                 address: bob_address,
                                 session_store: alice_store,
                                 identity_store: alice_store,
                                 ctx: nil)

        // Bob does the same:
        try! bob_store.storePreKey(id: prekey_id,
                                   record: PreKeyRecord(id: prekey_id, priv_key: bob_pre_key),
                                   ctx: nil);

        try! bob_store.storeSignedPreKey(id: signed_prekey_id,
                                         record: SignedPreKeyRecord(
                                           id: signed_prekey_id,
                                           timestamp: 42000,
                                           priv_key: bob_signed_pre_key,
                                           signature: bob_signed_pre_key_signature
                                         ),
                                         ctx: nil);

        // Alice sends a message:
        let ptext_a : [UInt8] = [8,6,7,5,3,0,9];

        let ctext_a = try! SignalEncrypt(message: ptext_a,
                                         address: bob_address,
                                         session_store: alice_store,
                                         identity_store: alice_store,
                                         ctx: nil)

        XCTAssertEqual(try! ctext_a.messageType(), 3); // prekey

        let ctext_b = try! PreKeySignalMessage(bytes: try! ctext_a.serialize())

        let ptext_b = try! SignalDecryptPreKey(message: ctext_b,
                                               address: alice_address,
                                               session_store: bob_store,
                                               identity_store: bob_store,
                                               pre_key_store: bob_store,
                                               signed_pre_key_store: bob_store,
                                               ctx: nil)

        XCTAssertEqual(ptext_a, ptext_b)

        // Bob replies
        let ptext2_b : [UInt8] = [23];

        let ctext2_b = try! SignalEncrypt(message: ptext2_b,
                                          address: alice_address,
                                          session_store: bob_store,
                                          identity_store: bob_store,
                                          ctx: nil)

        XCTAssertEqual(try! ctext2_b.messageType(), 2); // normal message

        let ctext2_a = try! SignalMessage(bytes: try! ctext2_b.serialize())

        let ptext2_a = try! SignalDecrypt(message: ctext2_a,
                                          address: bob_address,
                                          session_store: alice_store,
                                          identity_store: alice_store,
                                          ctx: nil)

        XCTAssertEqual(ptext2_a, ptext2_b)
    }

    static var allTests: [(String, (SwiftSignalTests) -> () throws -> Void)] {
        return [
          ("testAddreses", testAddress),
          ("testFingerprint", testFingerprint),
          ("testPkOperations", testPkOperations),
          ("testHkdf", testHkdf),
          ("testGroupCipher", testGroupCipher),
          ("testSessionCipher", testSessionCipher),
        ]
    }
}
