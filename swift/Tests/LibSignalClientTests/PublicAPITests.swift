//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import LibSignalClient
import XCTest

class PublicAPITests: TestCaseBase {
    func testHkdfSimple() {
        let ikm: [UInt8] = [
            0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
            0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
        ]
        let info: [UInt8] = []
        let salt: [UInt8] = []
        let okm: [UInt8] = [0x8D, 0xA4, 0xE7, 0x75]

        let derived = try! hkdf(
            outputLength: okm.count,
            inputKeyMaterial: ikm,
            salt: salt,
            info: info
        )
        XCTAssertEqual(derived, okm)
    }

    func testHkdfUsingRFCExample() {
        // https://tools.ietf.org/html/rfc5869 A.2
        let ikm: [UInt8] = Array(0...0x4F)
        let salt: [UInt8] = Array(0x60...0xAF)
        let info: [UInt8] = Array(0xB0...0xFF)
        let okm: [UInt8] = [
            0xB1,
            0x1E,
            0x39,
            0x8D,
            0xC8,
            0x03,
            0x27,
            0xA1,
            0xC8,
            0xE7,
            0xF7,
            0x8C,
            0x59,
            0x6A,
            0x49,
            0x34,
            0x4F,
            0x01,
            0x2E,
            0xDA,
            0x2D,
            0x4E,
            0xFA,
            0xD8,
            0xA0,
            0x50,
            0xCC,
            0x4C,
            0x19,
            0xAF,
            0xA9,
            0x7C,
            0x59,
            0x04,
            0x5A,
            0x99,
            0xCA,
            0xC7,
            0x82,
            0x72,
            0x71,
            0xCB,
            0x41,
            0xC6,
            0x5E,
            0x59,
            0x0E,
            0x09,
            0xDA,
            0x32,
            0x75,
            0x60,
            0x0C,
            0x2F,
            0x09,
            0xB8,
            0x36,
            0x77,
            0x93,
            0xA9,
            0xAC,
            0xA3,
            0xDB,
            0x71,
            0xCC,
            0x30,
            0xC5,
            0x81,
            0x79,
            0xEC,
            0x3E,
            0x87,
            0xC1,
            0x4C,
            0x01,
            0xD5,
            0xC1,
            0xF3,
            0x43,
            0x4F,
            0x1D,
            0x87,
        ]

        let derived = try! hkdf(
            outputLength: okm.count,
            inputKeyMaterial: ikm,
            salt: salt,
            info: info
        )
        XCTAssertEqual(derived, okm)
    }

    func testAddress() {
        let addr = try! ProtocolAddress(name: "addr1", deviceId: 5)
        XCTAssertEqual(addr.name, "addr1")
        XCTAssertEqual(addr.deviceId, 5)
    }

    func testAddressRoundTripServiceId() {
        let uuid = UUID()
        let aci = Aci(fromUUID: uuid)
        let pni = Pni(fromUUID: uuid)

        let aciAddr = ProtocolAddress(aci, deviceId: 1)
        let pniAddr = ProtocolAddress(pni, deviceId: 1)
        XCTAssertNotEqual(aciAddr, pniAddr)
        XCTAssertEqual(aci, aciAddr.serviceId)
        XCTAssertEqual(pni, pniAddr.serviceId)
    }

    func testPkOperations() {
        let sk = PrivateKey.generate()
        let sk_bytes = sk.serialize()

        let pk = sk.publicKey
        let pk_bytes = pk.serialize()
        XCTAssertEqual(pk_bytes[0], 0x05) // DJB
        XCTAssertEqual(pk_bytes.count, 33)

        let pk_raw = pk.keyBytes
        XCTAssertEqual(pk_raw.count, 32)
        XCTAssertEqual(pk_raw[0...31], pk_bytes[1...32])

        let sk_reloaded = try! PrivateKey(sk_bytes)
        let pk_reloaded = sk_reloaded.publicKey

        XCTAssertEqual(pk, pk_reloaded)

        XCTAssertEqual(pk.serialize(), pk_reloaded.serialize())

        var message: [UInt8] = [1, 2, 3]
        var signature = sk.generateSignature(message: message)

        XCTAssertEqual(try! pk.verifySignature(message: message, signature: signature), true)

        signature[5] ^= 1
        XCTAssertEqual(try! pk.verifySignature(message: message, signature: signature), false)
        signature[5] ^= 1
        XCTAssertEqual(try! pk.verifySignature(message: message, signature: signature), true)
        message[1] ^= 1
        XCTAssertEqual(try! pk.verifySignature(message: message, signature: signature), false)
        message[1] ^= 1
        XCTAssertEqual(try! pk.verifySignature(message: message, signature: signature), true)

        let sk2 = PrivateKey.generate()

        let shared_secret1 = sk.keyAgreement(with: sk2.publicKey)
        let shared_secret2 = sk2.keyAgreement(with: sk.publicKey)

        XCTAssertEqual(shared_secret1, shared_secret2)
    }

    func testFingerprint() {
        let ALICE_IDENTITY: [UInt8] = [0x05, 0x06, 0x86, 0x3B, 0xC6, 0x6D, 0x02, 0xB4, 0x0D, 0x27, 0xB8, 0xD4, 0x9C, 0xA7, 0xC0, 0x9E, 0x92, 0x39, 0x23, 0x6F, 0x9D, 0x7D, 0x25, 0xD6, 0xFC, 0xCA, 0x5C, 0xE1, 0x3C, 0x70, 0x64, 0xD8, 0x68]
        let BOB_IDENTITY: [UInt8] = [0x05, 0xF7, 0x81, 0xB6, 0xFB, 0x32, 0xFE, 0xD9, 0xBA, 0x1C, 0xF2, 0xDE, 0x97, 0x8D, 0x4D, 0x5D, 0xA2, 0x8D, 0xC3, 0x40, 0x46, 0xAE, 0x81, 0x44, 0x02, 0xB5, 0xC0, 0xDB, 0xD9, 0x6F, 0xDA, 0x90, 0x7B]

        let VERSION_1 = 1
        let DISPLAYABLE_FINGERPRINT_V1 = "300354477692869396892869876765458257569162576843440918079131"
        let ALICE_SCANNABLE_FINGERPRINT_V1: [UInt8] = [0x08, 0x01, 0x12, 0x22, 0x0A, 0x20, 0x1E, 0x30, 0x1A, 0x03, 0x53, 0xDC, 0xE3, 0xDB, 0xE7, 0x68, 0x4C, 0xB8, 0x33, 0x6E, 0x85, 0x13, 0x6C, 0xDC, 0x0E, 0xE9, 0x62, 0x19, 0x49, 0x4A, 0xDA, 0x30, 0x5D, 0x62, 0xA7, 0xBD, 0x61, 0xDF, 0x1A, 0x22, 0x0A, 0x20, 0xD6, 0x2C, 0xBF, 0x73, 0xA1, 0x15, 0x92, 0x01, 0x5B, 0x6B, 0x9F, 0x16, 0x82, 0xAC, 0x30, 0x6F, 0xEA, 0x3A, 0xAF, 0x38, 0x85, 0xB8, 0x4D, 0x12, 0xBC, 0xA6, 0x31, 0xE9, 0xD4, 0xFB, 0x3A, 0x4D]
        let BOB_SCANNABLE_FINGERPRINT_V1: [UInt8] = [0x08, 0x01, 0x12, 0x22, 0x0A, 0x20, 0xD6, 0x2C, 0xBF, 0x73, 0xA1, 0x15, 0x92, 0x01, 0x5B, 0x6B, 0x9F, 0x16, 0x82, 0xAC, 0x30, 0x6F, 0xEA, 0x3A, 0xAF, 0x38, 0x85, 0xB8, 0x4D, 0x12, 0xBC, 0xA6, 0x31, 0xE9, 0xD4, 0xFB, 0x3A, 0x4D, 0x1A, 0x22, 0x0A, 0x20, 0x1E, 0x30, 0x1A, 0x03, 0x53, 0xDC, 0xE3, 0xDB, 0xE7, 0x68, 0x4C, 0xB8, 0x33, 0x6E, 0x85, 0x13, 0x6C, 0xDC, 0x0E, 0xE9, 0x62, 0x19, 0x49, 0x4A, 0xDA, 0x30, 0x5D, 0x62, 0xA7, 0xBD, 0x61, 0xDF]

        let VERSION_2 = 2
        let DISPLAYABLE_FINGERPRINT_V2 = DISPLAYABLE_FINGERPRINT_V1
        let ALICE_SCANNABLE_FINGERPRINT_V2: [UInt8] = [0x08, 0x02, 0x12, 0x22, 0x0A, 0x20, 0x1E, 0x30, 0x1A, 0x03, 0x53, 0xDC, 0xE3, 0xDB, 0xE7, 0x68, 0x4C, 0xB8, 0x33, 0x6E, 0x85, 0x13, 0x6C, 0xDC, 0x0E, 0xE9, 0x62, 0x19, 0x49, 0x4A, 0xDA, 0x30, 0x5D, 0x62, 0xA7, 0xBD, 0x61, 0xDF, 0x1A, 0x22, 0x0A, 0x20, 0xD6, 0x2C, 0xBF, 0x73, 0xA1, 0x15, 0x92, 0x01, 0x5B, 0x6B, 0x9F, 0x16, 0x82, 0xAC, 0x30, 0x6F, 0xEA, 0x3A, 0xAF, 0x38, 0x85, 0xB8, 0x4D, 0x12, 0xBC, 0xA6, 0x31, 0xE9, 0xD4, 0xFB, 0x3A, 0x4D]
        let BOB_SCANNABLE_FINGERPRINT_V2: [UInt8] = [0x08, 0x02, 0x12, 0x22, 0x0A, 0x20, 0xD6, 0x2C, 0xBF, 0x73, 0xA1, 0x15, 0x92, 0x01, 0x5B, 0x6B, 0x9F, 0x16, 0x82, 0xAC, 0x30, 0x6F, 0xEA, 0x3A, 0xAF, 0x38, 0x85, 0xB8, 0x4D, 0x12, 0xBC, 0xA6, 0x31, 0xE9, 0xD4, 0xFB, 0x3A, 0x4D, 0x1A, 0x22, 0x0A, 0x20, 0x1E, 0x30, 0x1A, 0x03, 0x53, 0xDC, 0xE3, 0xDB, 0xE7, 0x68, 0x4C, 0xB8, 0x33, 0x6E, 0x85, 0x13, 0x6C, 0xDC, 0x0E, 0xE9, 0x62, 0x19, 0x49, 0x4A, 0xDA, 0x30, 0x5D, 0x62, 0xA7, 0xBD, 0x61, 0xDF]

        // testVectorsVersion1
        let aliceStableId = [UInt8]("+14152222222".utf8)
        let bobStableId = [UInt8]("+14153333333".utf8)

        let aliceIdentityKey = try! PublicKey(ALICE_IDENTITY)
        let bobIdentityKey = try! PublicKey(BOB_IDENTITY)

        let generator = NumericFingerprintGenerator(iterations: 5200)

        let aliceFingerprint = try! generator.create(
            version: VERSION_1,
            localIdentifier: aliceStableId,
            localKey: aliceIdentityKey,
            remoteIdentifier: bobStableId,
            remoteKey: bobIdentityKey
        )

        let bobFingerprint = try! generator.create(
            version: VERSION_1,
            localIdentifier: bobStableId,
            localKey: bobIdentityKey,
            remoteIdentifier: aliceStableId,
            remoteKey: aliceIdentityKey
        )

        XCTAssertEqual(aliceFingerprint.displayable.formatted, DISPLAYABLE_FINGERPRINT_V1)
        XCTAssertEqual(bobFingerprint.displayable.formatted, DISPLAYABLE_FINGERPRINT_V1)

        XCTAssertEqual(aliceFingerprint.scannable.encoding, ALICE_SCANNABLE_FINGERPRINT_V1)
        XCTAssertEqual(bobFingerprint.scannable.encoding, BOB_SCANNABLE_FINGERPRINT_V1)

        XCTAssertTrue(try! bobFingerprint.scannable.compare(againstEncoding: aliceFingerprint.scannable.encoding))
        XCTAssertTrue(try! aliceFingerprint.scannable.compare(againstEncoding: bobFingerprint.scannable.encoding))

        // testVectorsVersion2

        let aliceFingerprint2 = try! generator.create(
            version: VERSION_2,
            localIdentifier: aliceStableId,
            localKey: aliceIdentityKey,
            remoteIdentifier: bobStableId,
            remoteKey: bobIdentityKey
        )

        let bobFingerprint2 = try! generator.create(
            version: VERSION_2,
            localIdentifier: bobStableId,
            localKey: bobIdentityKey,
            remoteIdentifier: aliceStableId,
            remoteKey: aliceIdentityKey
        )

        XCTAssertEqual(aliceFingerprint2.displayable.formatted, DISPLAYABLE_FINGERPRINT_V2)
        XCTAssertEqual(bobFingerprint2.displayable.formatted, DISPLAYABLE_FINGERPRINT_V2)

        XCTAssertEqual(aliceFingerprint2.scannable.encoding, ALICE_SCANNABLE_FINGERPRINT_V2)
        XCTAssertEqual(bobFingerprint2.scannable.encoding, BOB_SCANNABLE_FINGERPRINT_V2)

        XCTAssertTrue(try! bobFingerprint2.scannable.compare(againstEncoding: aliceFingerprint2.scannable.encoding))
        XCTAssertTrue(try! aliceFingerprint2.scannable.compare(againstEncoding: bobFingerprint2.scannable.encoding))

        XCTAssertThrowsError(try bobFingerprint2.scannable.compare(againstEncoding: aliceFingerprint.scannable.encoding))
        XCTAssertThrowsError(try bobFingerprint.scannable.compare(againstEncoding: aliceFingerprint2.scannable.encoding))

        // testMismatchingFingerprints

        let mitmIdentityKey = PrivateKey.generate().publicKey

        let aliceFingerprintM = try! generator.create(
            version: VERSION_1,
            localIdentifier: aliceStableId,
            localKey: aliceIdentityKey,
            remoteIdentifier: bobStableId,
            remoteKey: mitmIdentityKey
        )

        let bobFingerprintM = try! generator.create(
            version: VERSION_1,
            localIdentifier: bobStableId,
            localKey: bobIdentityKey,
            remoteIdentifier: aliceStableId,
            remoteKey: aliceIdentityKey
        )

        XCTAssertNotEqual(
            aliceFingerprintM.displayable.formatted,
            bobFingerprintM.displayable.formatted
        )

        XCTAssertFalse(try! bobFingerprintM.scannable.compare(againstEncoding: aliceFingerprintM.scannable.encoding))
        XCTAssertFalse(try! aliceFingerprintM.scannable.compare(againstEncoding: bobFingerprintM.scannable.encoding))

        XCTAssertEqual(aliceFingerprintM.displayable.formatted.count, 60)

        // testMismatchingIdentifiers

        let badBobStableId = [UInt8]("+14153333334".utf8)

        let aliceFingerprintI = try! generator.create(
            version: VERSION_1,
            localIdentifier: aliceStableId,
            localKey: aliceIdentityKey,
            remoteIdentifier: badBobStableId,
            remoteKey: bobIdentityKey
        )

        let bobFingerprintI = try! generator.create(
            version: VERSION_1,
            localIdentifier: bobStableId,
            localKey: bobIdentityKey,
            remoteIdentifier: aliceStableId,
            remoteKey: aliceIdentityKey
        )

        XCTAssertNotEqual(
            aliceFingerprintI.displayable.formatted,
            bobFingerprintI.displayable.formatted
        )

        XCTAssertFalse(try! bobFingerprintI.scannable.compare(againstEncoding: aliceFingerprintI.scannable.encoding))
        XCTAssertFalse(try! aliceFingerprintI.scannable.compare(againstEncoding: bobFingerprintI.scannable.encoding))

        // Test bad fingerprint
        XCTAssertThrowsError(try aliceFingerprintI.scannable.compare(againstEncoding: []))
    }

    func testGroupCipher() {
        let sender = try! ProtocolAddress(name: "+14159999111", deviceId: 4)
        let distribution_id = UUID(uuidString: "d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")!

        let a_store = InMemorySignalProtocolStore()

        let skdm = try! SenderKeyDistributionMessage(from: sender, distributionId: distribution_id, store: a_store, context: NullContext())

        let skdm_bits = skdm.serialize()

        let skdm_r = try! SenderKeyDistributionMessage(bytes: skdm_bits)

        let a_ctext = try! groupEncrypt([1, 2, 3], from: sender, distributionId: distribution_id, store: a_store, context: NullContext()).serialize()

        let b_store = InMemorySignalProtocolStore()
        try! processSenderKeyDistributionMessage(
            skdm_r,
            from: sender,
            store: b_store,
            context: NullContext()
        )
        let b_ptext = try! groupDecrypt(a_ctext, from: sender, store: b_store, context: NullContext())

        XCTAssertEqual(b_ptext, [1, 2, 3])
    }

    func testGroupCipherWithContext() {
        class ContextUsingStore: InMemorySignalProtocolStore {
            var expectedContext: StoreContext & AnyObject

            init(expectedContext: StoreContext & AnyObject) {
                self.expectedContext = expectedContext
                super.init()
            }

            override func loadSenderKey(from sender: ProtocolAddress, distributionId: UUID, context: StoreContext) throws -> SenderKeyRecord? {
                XCTAssertIdentical(self.expectedContext, context as AnyObject)
                return try super.loadSenderKey(from: sender, distributionId: distributionId, context: context)
            }
        }

        class ContextWithIdentity: StoreContext {}

        let sender = try! ProtocolAddress(name: "+14159999111", deviceId: 4)
        let distribution_id = UUID(uuidString: "d1d1d1d1-7000-11eb-b32a-33b8a8a487a6")!

        let a_store = ContextUsingStore(expectedContext: ContextWithIdentity())

        let skdm = try! SenderKeyDistributionMessage(from: sender, distributionId: distribution_id, store: a_store, context: a_store.expectedContext)

        let skdm_bits = skdm.serialize()

        _ = try! SenderKeyDistributionMessage(bytes: skdm_bits)

        _ = try! groupEncrypt([1, 2, 3], from: sender, distributionId: distribution_id, store: a_store, context: a_store.expectedContext).serialize()
    }

    func testSenderCertificates() {
        let senderCertBits: [UInt8] = [
            0x0A, 0xCD, 0x01, 0x0A, 0x0C, 0x2B, 0x31, 0x34, 0x31, 0x35, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x32, 0x10, 0x2A, 0x19,
            0x2D, 0x63, 0xB5, 0x5F, 0x00, 0x00, 0x00, 0x00, 0x22, 0x21, 0x05, 0xBB, 0x25, 0x64, 0x9C, 0x79, 0x4B, 0xB4, 0x6C, 0x8C,
            0x57, 0x97, 0x69, 0x3C, 0xC8, 0x05, 0xB1, 0xB8, 0x46, 0xDA, 0x91, 0x17, 0x6F, 0xEC, 0x6A, 0x3E, 0xF2, 0x1F, 0x41, 0x0B,
            0xE9, 0x60, 0x43, 0x2A, 0x69, 0x0A, 0x25, 0x08, 0x01, 0x12, 0x21, 0x05, 0x4F, 0xBF, 0xFA, 0x55, 0xEB, 0xD5, 0x23, 0xD2,
            0x55, 0x16, 0x96, 0x0C, 0xED, 0x28, 0x99, 0xF2, 0x6A, 0x72, 0xFE, 0x26, 0xD0, 0xE0, 0x2A, 0x9D, 0xAE, 0x81, 0x67, 0x1F,
            0x46, 0x5B, 0xA1, 0x1D, 0x12, 0x40, 0x7A, 0xBF, 0xDB, 0x83, 0x6C, 0x15, 0xCB, 0x3A, 0x8C, 0x61, 0x76, 0xB3, 0x30, 0x70,
            0xDF, 0xBC, 0x47, 0xEA, 0x4A, 0x90, 0x52, 0x35, 0x3A, 0xC4, 0x2F, 0xB8, 0x7E, 0x4E, 0x4D, 0x33, 0x4F, 0x69, 0xA5, 0xE0,
            0xD4, 0xAB, 0xD2, 0xDD, 0x81, 0x9F, 0x61, 0xA2, 0xC0, 0x2A, 0x51, 0xC2, 0x74, 0x51, 0xC9, 0x31, 0xAA, 0x85, 0x35, 0xF8,
            0x32, 0x8D, 0x1E, 0xC8, 0xCE, 0x7A, 0x2B, 0x9A, 0x9E, 0x01, 0x32, 0x24, 0x39, 0x64, 0x30, 0x36, 0x35, 0x32, 0x61, 0x33,
            0x2D, 0x64, 0x63, 0x63, 0x33, 0x2D, 0x34, 0x64, 0x31, 0x31, 0x2D, 0x39, 0x37, 0x35, 0x66, 0x2D, 0x37, 0x34, 0x64, 0x36,
            0x31, 0x35, 0x39, 0x38, 0x37, 0x33, 0x33, 0x66, 0x12, 0x40, 0x06, 0x8B, 0xF0, 0xC5, 0xE8, 0x99, 0x83, 0x81, 0x28, 0xBD,
            0x36, 0xD9, 0x2B, 0x01, 0xEC, 0xA9, 0x95, 0x9D, 0x00, 0xF2, 0xDB, 0x0B, 0xCB, 0xB6, 0x8B, 0x2A, 0x62, 0xD4, 0xDF, 0x46,
            0xDB, 0xB4, 0x50, 0x14, 0x9E, 0x9D, 0xCB, 0xC6, 0xBD, 0xDB, 0x2B, 0x28, 0x98, 0xFC, 0xD5, 0xFF, 0x5C, 0xAF, 0x1B, 0x8C,
            0xF7, 0x2B, 0x36, 0xFF, 0xFE, 0x2F, 0x55, 0xF3, 0xEC, 0xEB, 0xAB, 0x25, 0x47, 0x88,
        ]

        let senderCert = try! SenderCertificate(senderCertBits)

        XCTAssertEqual(senderCert.serialize(), senderCertBits)
        XCTAssertEqual(senderCert.expiration, 1_605_722_925)

        XCTAssertEqual(senderCert.deviceId, 42)

        XCTAssertEqual(senderCert.publicKey.serialize().count, 33)

        XCTAssertEqual(senderCert.senderUuid, "9d0652a3-dcc3-4d11-975f-74d61598733f")
        XCTAssertEqual(senderCert.senderAci.serviceIdString, "9d0652a3-dcc3-4d11-975f-74d61598733f")
        XCTAssertEqual(senderCert.senderE164, Optional("+14152222222"))

        let serverCert = senderCert.serverCertificate

        XCTAssertEqual(serverCert.keyId, 1)
        XCTAssertEqual(serverCert.publicKey.serialize().count, 33)
        XCTAssertEqual(serverCert.signatureBytes.count, 64)
    }

    func testSenderCertificateGetSenderAci() {
        let aci = Aci(fromUUID: UUID())
        let trustRoot = IdentityKeyPair.generate()
        let serverKeys = IdentityKeyPair.generate()
        let serverCert = try! ServerCertificate(keyId: 1, publicKey: serverKeys.publicKey, trustRoot: trustRoot.privateKey)
        let senderAddr = try! SealedSenderAddress(aci: aci, deviceId: 1)
        let senderCert = try! SenderCertificate(
            sender: senderAddr,
            publicKey: IdentityKeyPair.generate().publicKey,
            expiration: 31337,
            signerCertificate: serverCert,
            signerKey: serverKeys.privateKey
        )

        XCTAssertNil(senderCert.senderE164)
        XCTAssertEqual(aci, senderCert.senderAci)
    }

    private func testRoundTrip<Handle>(_ initial: Handle, serialize: (Handle) -> [UInt8], deserialize: ([UInt8]) throws -> Handle, line: UInt = #line) {
        let bytes = serialize(initial)
        let roundTripBytes = serialize(try! deserialize(bytes))
        XCTAssertEqual(bytes, roundTripBytes, "\(Handle.self) did not round trip correctly", line: line)
    }

    func testSerializationRoundTrip() {
        let keyPair = IdentityKeyPair.generate()
        self.testRoundTrip(keyPair, serialize: { $0.serialize() }, deserialize: { try .init(bytes: $0) })
        self.testRoundTrip(keyPair.publicKey, serialize: { $0.serialize() }, deserialize: { try .init($0) })
        self.testRoundTrip(keyPair.privateKey, serialize: { $0.serialize() }, deserialize: { try .init($0) })
        self.testRoundTrip(keyPair.identityKey, serialize: { $0.serialize() }, deserialize: { try .init(bytes: $0) })

        let preKeyRecord = try! PreKeyRecord(id: 7, publicKey: keyPair.publicKey, privateKey: keyPair.privateKey)
        self.testRoundTrip(preKeyRecord, serialize: { $0.serialize() }, deserialize: { try .init(bytes: $0) })

        let signedPreKeyRecord = try! SignedPreKeyRecord(
            id: 77,
            timestamp: 42000,
            privateKey: keyPair.privateKey,
            signature: keyPair.privateKey.generateSignature(message: keyPair.publicKey.serialize())
        )
        self.testRoundTrip(signedPreKeyRecord, serialize: { $0.serialize() }, deserialize: { try .init(bytes: $0) })
    }

    func testDeviceTransferKey() {
        for keyFormat in KeyFormat.allCases {
            let deviceKey = DeviceTransferKey.generate(formattedAs: keyFormat)

            /*
             Anything encoded in an ASN.1 SEQUENCE starts with 0x30 when encoded
             as DER. (This test could be better.)
             */
            let key = deviceKey.privateKeyMaterial()
            XCTAssert(key.count > 0)
            XCTAssertEqual(key[0], 0x30)

            let cert = deviceKey.generateCertificate("name", 30)
            XCTAssert(cert.count > 0)
            XCTAssertEqual(cert[0], 0x30)
        }
    }

    func testSignAlternateIdentity() {
        let primary = IdentityKeyPair.generate()
        let secondary = IdentityKeyPair.generate()
        let signature = secondary.signAlternateIdentity(primary.identityKey)
        XCTAssert(try! secondary.identityKey.verifyAlternateIdentity(primary.identityKey, signature: signature))
    }

    func testPreKeyBundleAccessors() {
        let registrationId: UInt32 = 123
        let deviceId: UInt32 = 5
        let signedPreKeyId: UInt32 = 20
        let identityKeyPair = IdentityKeyPair.generate()
        let signedPreKey = IdentityKeyPair.generate().publicKey
        let signedPreKeySignature = identityKeyPair.privateKey.generateSignature(message: signedPreKey.serialize())

        let preKeyId: UInt32 = 10
        let preKey = IdentityKeyPair.generate().publicKey

        let kyberPreKeyId: UInt32 = 50
        let kyberPreKey = KEMKeyPair.generate().publicKey
        let kyberPreKeySignature = identityKeyPair.privateKey.generateSignature(message: kyberPreKey.serialize())

        func checkConsistentFields(_ bundle: PreKeyBundle) {
            XCTAssertEqual(bundle.registrationId, registrationId)
            XCTAssertEqual(bundle.deviceId, deviceId)
            XCTAssertEqual(bundle.signedPreKeyId, signedPreKeyId)
            XCTAssertEqual(bundle.signedPreKeyPublic, signedPreKey)
            XCTAssertEqual(bundle.signedPreKeySignature, signedPreKeySignature)
            XCTAssertEqual(bundle.identityKey, identityKeyPair.identityKey)
        }

        do {
            let bundle = try! PreKeyBundle(registrationId: registrationId, deviceId: deviceId, signedPrekeyId: signedPreKeyId, signedPrekey: signedPreKey, signedPrekeySignature: signedPreKeySignature, identity: identityKeyPair.identityKey)
            checkConsistentFields(bundle)
            XCTAssertNil(bundle.preKeyId)
            XCTAssertNil(bundle.preKeyPublic)
            XCTAssertNil(bundle.kyberPreKeyId)
            XCTAssertNil(bundle.kyberPreKeyPublic)
            XCTAssertNil(bundle.kyberPreKeySignature)
        }

        do {
            let bundle = try! PreKeyBundle(registrationId: registrationId, deviceId: deviceId, prekeyId: preKeyId, prekey: preKey, signedPrekeyId: signedPreKeyId, signedPrekey: signedPreKey, signedPrekeySignature: signedPreKeySignature, identity: identityKeyPair.identityKey)
            checkConsistentFields(bundle)
            XCTAssertEqual(bundle.preKeyId, preKeyId)
            XCTAssertEqual(bundle.preKeyPublic, preKey)
            XCTAssertNil(bundle.kyberPreKeyId)
            XCTAssertNil(bundle.kyberPreKeyPublic)
            XCTAssertNil(bundle.kyberPreKeySignature)
        }

        do {
            let bundle = try! PreKeyBundle(registrationId: registrationId, deviceId: deviceId, signedPrekeyId: signedPreKeyId, signedPrekey: signedPreKey, signedPrekeySignature: signedPreKeySignature, identity: identityKeyPair.identityKey, kyberPrekeyId: kyberPreKeyId, kyberPrekey: kyberPreKey, kyberPrekeySignature: kyberPreKeySignature)
            checkConsistentFields(bundle)
            XCTAssertNil(bundle.preKeyId)
            XCTAssertNil(bundle.preKeyPublic)
            XCTAssertEqual(bundle.kyberPreKeyId, kyberPreKeyId)
            XCTAssertEqual(bundle.kyberPreKeyPublic, kyberPreKey)
            XCTAssertEqual(bundle.kyberPreKeySignature, kyberPreKeySignature)
        }

        do {
            let bundle = try! PreKeyBundle(registrationId: registrationId, deviceId: deviceId, prekeyId: preKeyId, prekey: preKey, signedPrekeyId: signedPreKeyId, signedPrekey: signedPreKey, signedPrekeySignature: signedPreKeySignature, identity: identityKeyPair.identityKey, kyberPrekeyId: kyberPreKeyId, kyberPrekey: kyberPreKey, kyberPrekeySignature: kyberPreKeySignature)
            checkConsistentFields(bundle)
            XCTAssertEqual(bundle.preKeyId, preKeyId)
            XCTAssertEqual(bundle.preKeyPublic, preKey)
            XCTAssertEqual(bundle.kyberPreKeyId, kyberPreKeyId)
            XCTAssertEqual(bundle.kyberPreKeyPublic, kyberPreKey)
            XCTAssertEqual(bundle.kyberPreKeySignature, kyberPreKeySignature)
        }
    }
}
