//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import LibSignalClient
import XCTest

private let SECONDS_PER_DAY: UInt64 = 24 * 60 * 60

class ZKGroupTests: TestCaseBase {
    let TEST_ARRAY_16: UUID = .init(uuid: (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F))

    let TEST_ARRAY_16_1: UUID = .init(uuid: (0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73))

    let TEST_ARRAY_32: Randomness = .init((
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    ))

    let TEST_ARRAY_32_1: [UInt8] = [
        0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73,
        0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83,
    ]

    let TEST_ARRAY_32_2: Randomness = .init((
        0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7,
        0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7
    ))

    let TEST_ARRAY_32_3: Randomness = .init((
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
        28, 29, 30, 31, 32
    ))

    let TEST_ARRAY_32_4: Randomness = .init((
        2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
        28, 29, 30, 31, 32, 33
    ))

    let TEST_ARRAY_32_5: Randomness = .init((
        0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22
    ))

    let authPresentationResult: [UInt8] = [
        0x01, 0x32, 0x2F, 0x91, 0x00, 0xDE, 0x07, 0x34, 0x55, 0x0A, 0x81, 0xDC, 0x81, 0x72, 0x4A, 0x81,
        0xDB, 0xD3, 0xB1, 0xB4, 0x3D, 0xBC, 0x1D, 0x55, 0x2D, 0x53, 0x45, 0x59, 0x11, 0xC2, 0x77, 0x2F,
        0x34, 0xA6, 0x35, 0x6C, 0xA1, 0x7C, 0x6D, 0x34, 0xD8, 0x58, 0x39, 0x14, 0x56, 0xAF, 0x55, 0xD0,
        0xEF, 0x84, 0x1F, 0xBE, 0x1F, 0xA8, 0xC4, 0xEE, 0x81, 0x0F, 0x21, 0xE0, 0xBB, 0x9F, 0x4A, 0xCE,
        0x4C, 0x5C, 0x48, 0xC7, 0x2E, 0xBB, 0xEB, 0x2C, 0xCD, 0xA5, 0xF7, 0xAA, 0x49, 0xAE, 0xE6, 0xBC,
        0x00, 0x51, 0xCD, 0xDE, 0x16, 0x6E, 0x0F, 0x8C, 0x5F, 0x1F, 0xEB, 0xD5, 0x3A, 0x44, 0x37, 0xC5,
        0x70, 0xEE, 0x1A, 0xA2, 0x23, 0xF5, 0xEB, 0x93, 0x7D, 0xB9, 0x8F, 0x34, 0xE3, 0x65, 0x3D, 0x85,
        0xEC, 0x16, 0x3F, 0x39, 0x84, 0x72, 0x22, 0xA2, 0xDE, 0xC4, 0x23, 0x5E, 0xA4, 0x1C, 0x47, 0xBB,
        0x62, 0x02, 0x8A, 0xAE, 0x30, 0x94, 0x58, 0x57, 0xEE, 0x77, 0x66, 0x30, 0x79, 0xBC, 0xC4, 0x92,
        0x3D, 0x14, 0xA4, 0x3A, 0xD4, 0xF6, 0xBC, 0x33, 0x71, 0x50, 0x46, 0xF7, 0xBD, 0xE5, 0x27, 0x15,
        0x37, 0x5C, 0xA9, 0xF8, 0x9B, 0xE0, 0xE6, 0x30, 0xD4, 0xBD, 0xAA, 0x21, 0x11, 0x56, 0xD0, 0x30,
        0x67, 0x23, 0xF5, 0x43, 0xB0, 0x6F, 0x5E, 0x99, 0x84, 0x47, 0xB9, 0x62, 0xC8, 0xE9, 0x72, 0x9B,
        0x4C, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0xD0, 0xEA, 0xE8, 0xE4, 0x31, 0x1A,
        0x6A, 0xE3, 0xD2, 0x97, 0x0E, 0xF1, 0x98, 0xC3, 0x98, 0x11, 0x04, 0x62, 0xBE, 0x47, 0xDD, 0x2F,
        0x26, 0xE6, 0x55, 0x92, 0x09, 0xEF, 0x6C, 0xC2, 0x00, 0x01, 0xA0, 0x5A, 0x0B, 0x31, 0x9A, 0x17,
        0x2D, 0xBE, 0xB2, 0x29, 0x3C, 0xC1, 0xE0, 0xE1, 0x91, 0xCE, 0xFB, 0x23, 0xE2, 0x4C, 0xF0, 0xD6,
        0xB4, 0xB5, 0x37, 0x3A, 0x30, 0x04, 0x4B, 0xE1, 0x0C, 0xB0, 0x33, 0x67, 0x4D, 0x63, 0x1E, 0x17,
        0xDF, 0xCE, 0x09, 0x39, 0x8F, 0x23, 0x4E, 0x9D, 0x62, 0xE1, 0x18, 0xA6, 0x07, 0x7C, 0xAE, 0xA0,
        0xEF, 0x8B, 0xF6, 0x7D, 0x7D, 0x72, 0x3D, 0xB7, 0x0F, 0xEC, 0xF2, 0x09, 0x8F, 0xA0, 0x41, 0x31,
        0x7B, 0x7B, 0xE9, 0xFD, 0xBB, 0x68, 0xB0, 0xF2, 0x5F, 0x5C, 0x47, 0x9D, 0x68, 0xBD, 0x91, 0x7F,
        0xC6, 0xF1, 0x87, 0xC5, 0xBF, 0x7A, 0x58, 0x91, 0x02, 0x31, 0x92, 0x1F, 0xC4, 0x35, 0x65, 0x23,
        0x24, 0x66, 0x32, 0x5C, 0x03, 0x92, 0x12, 0x36, 0x2B, 0x6D, 0x12, 0x03, 0xCC, 0xAE, 0xDF, 0x83,
        0x1D, 0xC7, 0xF9, 0x06, 0x0D, 0xCA, 0xAF, 0xFA, 0x02, 0x62, 0x40, 0x42, 0x17, 0x1F, 0x5F, 0x0E,
        0x78, 0x0B, 0x9F, 0x74, 0xCF, 0xA8, 0x8A, 0x14, 0x7F, 0x3F, 0x1C, 0x08, 0x2F, 0x9C, 0xA8, 0x63,
        0x8A, 0xF1, 0x78, 0x8E, 0x78, 0x99, 0xCB, 0xAE, 0x0C, 0x76, 0x5D, 0xE9, 0xDF, 0x4C, 0xFA, 0x54,
        0x87, 0xF3, 0x60, 0xE2, 0x9E, 0x99, 0x34, 0x3E, 0x91, 0x81, 0x1B, 0xAE, 0xC3, 0x31, 0xC4, 0x68,
        0x09, 0x85, 0xE6, 0x08, 0xCA, 0x5D, 0x40, 0x8E, 0x21, 0x72, 0x5C, 0x6A, 0xA1, 0xB6, 0x1D, 0x5A,
        0x8B, 0x48, 0xD7, 0x5F, 0x4A, 0xAA, 0x9A, 0x3C, 0xBE, 0x88, 0xD3, 0xE0, 0xF1, 0xA5, 0x43, 0x19,
        0x08, 0x1F, 0x77, 0xC7, 0x2C, 0x8F, 0x52, 0x54, 0x74, 0x40, 0xE2, 0x01, 0x00,
    ]

    let serverSignatureResult: [UInt8] = [
        0x87, 0xD3, 0x54, 0x56, 0x4D, 0x35, 0xEF, 0x91, 0xED, 0xBA, 0x85, 0x1E, 0x08, 0x15, 0x61, 0x2E,
        0x86, 0x4C, 0x22, 0x7A, 0x04, 0x71, 0xD5, 0x0C, 0x27, 0x06, 0x98, 0x60, 0x44, 0x06, 0xD0, 0x03,
        0xA5, 0x54, 0x73, 0xF5, 0x76, 0xCF, 0x24, 0x1F, 0xC6, 0xB4, 0x1C, 0x6B, 0x16, 0xE5, 0xE6, 0x3B,
        0x33, 0x3C, 0x02, 0xFE, 0x4A, 0x33, 0x85, 0x80, 0x22, 0xFD, 0xD7, 0xA4, 0xAB, 0x36, 0x7B, 0x06,
    ]

    func testSerializeRoundTrip() throws {
        let serverSecretParams = try ServerSecretParams.generate(randomness: self.TEST_ARRAY_32)
        let serializedSecretParams = serverSecretParams.serialize()
        XCTAssertEqual(serializedSecretParams, try ServerSecretParams(contents: serializedSecretParams).serialize())

        let serverPublicParams = try serverSecretParams.getPublicParams()
        let serializedPublicParams = serverPublicParams.serialize()
        XCTAssertEqual(serializedPublicParams, try ServerPublicParams(contents: serializedPublicParams).serialize())
    }

    func testAuthZkcIntegration() throws {
        let aci = Aci(fromUUID: TEST_ARRAY_16)
        let pni = Pni(fromUUID: TEST_ARRAY_16_1)
        let redemptionTime: UInt64 = 123_456 * SECONDS_PER_DAY

        // Generate keys (client's are per-group, server's are not)
        // ---

        // SERVER
        let serverSecretParams = try ServerSecretParams.generate(randomness: self.TEST_ARRAY_32)
        let serverPublicParams = try serverSecretParams.getPublicParams()
        let serverZkAuth = ServerZkAuthOperations(serverSecretParams: serverSecretParams)

        // CLIENT
        let masterKey = try GroupMasterKey(contents: TEST_ARRAY_32_1)
        let groupSecretParams = try GroupSecretParams.deriveFromMasterKey(groupMasterKey: masterKey)

        XCTAssertEqual((try groupSecretParams.getMasterKey()).serialize(), masterKey.serialize())

        let groupPublicParams = try groupSecretParams.getPublicParams()

        // SERVER
        // Issue credential
        let authCredentialResponse = try serverZkAuth.issueAuthCredentialWithPniZkc(randomness: self.TEST_ARRAY_32_2, aci: aci, pni: pni, redemptionTime: redemptionTime)

        // CLIENT
        // Receive credential
        let clientZkAuthCipher = ClientZkAuthOperations(serverPublicParams: serverPublicParams)
        let clientZkGroupCipher = ClientZkGroupCipher(groupSecretParams: groupSecretParams)
        let authCredential = try clientZkAuthCipher.receiveAuthCredentialWithPniAsServiceId(aci: aci, pni: pni, redemptionTime: redemptionTime, authCredentialResponse: authCredentialResponse)

        // Create and decrypt user entry
        let aciCiphertext = try clientZkGroupCipher.encrypt(aci)
        let aciPlaintext = try clientZkGroupCipher.decrypt(aciCiphertext)
        XCTAssertEqual(aci, aciPlaintext)
        let pniCiphertext = try clientZkGroupCipher.encrypt(pni)
        let pniPlaintext = try clientZkGroupCipher.decrypt(pniCiphertext)
        XCTAssertEqual(pni, pniPlaintext)

        // Create presentation
        let presentation = try clientZkAuthCipher.createAuthCredentialPresentation(randomness: self.TEST_ARRAY_32_5, groupSecretParams: groupSecretParams, authCredential: authCredential)

        // Verify presentation
        let uuidCiphertextRecv = try presentation.getUuidCiphertext()
        XCTAssertEqual(aciCiphertext.serialize(), uuidCiphertextRecv.serialize())
        XCTAssertEqual(pniCiphertext.serialize(), try presentation.getPniCiphertext().serialize())
        XCTAssertEqual(try presentation.getRedemptionTime(), Date(timeIntervalSince1970: TimeInterval(redemptionTime)))
        try serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams: groupPublicParams, authCredentialPresentation: presentation, now: Date(timeIntervalSince1970: TimeInterval(redemptionTime)))
    }

    func testExpiringProfileKeyIntegration() throws {
        let userId = Aci(fromUUID: TEST_ARRAY_16)
        // Generate keys (client's are per-group, server's are not)
        // ---

        // SERVER
        let serverSecretParams = try ServerSecretParams.generate(randomness: self.TEST_ARRAY_32)
        let serverPublicParams = try serverSecretParams.getPublicParams()
        let serverZkProfile = ServerZkProfileOperations(serverSecretParams: serverSecretParams)

        // CLIENT
        let masterKey = try GroupMasterKey(contents: TEST_ARRAY_32_1)
        let groupSecretParams = try GroupSecretParams.deriveFromMasterKey(groupMasterKey: masterKey)

        XCTAssertEqual(try groupSecretParams.getMasterKey().serialize(), masterKey.serialize())

        let groupPublicParams = try groupSecretParams.getPublicParams()
        let clientZkProfileCipher = ClientZkProfileOperations(serverPublicParams: serverPublicParams)

        let profileKey = try ProfileKey(contents: TEST_ARRAY_32_1)
        let profileKeyCommitment = try profileKey.getCommitment(userId: userId)

        // Create context and request
        let context = try clientZkProfileCipher.createProfileKeyCredentialRequestContext(randomness: self.TEST_ARRAY_32_3, userId: userId, profileKey: profileKey)
        let request = try context.getRequest()

        // SERVER
        let now = UInt64(Date().timeIntervalSince1970)
        let startOfDay = now - (now % SECONDS_PER_DAY)
        let expiration = startOfDay + 5 * SECONDS_PER_DAY
        let response = try serverZkProfile.issueExpiringProfileKeyCredential(randomness: self.TEST_ARRAY_32_4, profileKeyCredentialRequest: request, userId: userId, profileKeyCommitment: profileKeyCommitment, expiration: expiration)

        // CLIENT
        // Gets stored profile credential
        let clientZkGroupCipher = ClientZkGroupCipher(groupSecretParams: groupSecretParams)
        let profileKeyCredential = try clientZkProfileCipher.receiveExpiringProfileKeyCredential(profileKeyCredentialRequestContext: context, profileKeyCredentialResponse: response)

        // Create encrypted UID and profile key
        let uuidCiphertext = try clientZkGroupCipher.encrypt(userId)
        let plaintext = try clientZkGroupCipher.decrypt(uuidCiphertext)
        XCTAssertEqual(plaintext, userId)

        let profileKeyCiphertext = try clientZkGroupCipher.encryptProfileKey(profileKey: profileKey, userId: userId)
        let decryptedProfileKey = try clientZkGroupCipher.decryptProfileKey(profileKeyCiphertext: profileKeyCiphertext, userId: userId)
        XCTAssertEqual(profileKey.serialize(), decryptedProfileKey.serialize())

        XCTAssertEqual(Date(timeIntervalSince1970: TimeInterval(expiration)), profileKeyCredential.expirationTime)

        let presentation = try clientZkProfileCipher.createProfileKeyCredentialPresentation(randomness: self.TEST_ARRAY_32_5, groupSecretParams: groupSecretParams, profileKeyCredential: profileKeyCredential)

        // Verify presentation
        try serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams: groupPublicParams, profileKeyCredentialPresentation: presentation)
        try serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams: groupPublicParams, profileKeyCredentialPresentation: presentation, now: Date(timeIntervalSince1970: TimeInterval(expiration - 5)))
        XCTAssertThrowsError(try serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams: groupPublicParams, profileKeyCredentialPresentation: presentation, now: Date(timeIntervalSince1970: TimeInterval(expiration))))
        XCTAssertThrowsError(try serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams: groupPublicParams, profileKeyCredentialPresentation: presentation, now: Date(timeIntervalSince1970: TimeInterval(expiration + 5))))

        let uuidCiphertextRecv = try presentation.getUuidCiphertext()
        XCTAssertEqual(uuidCiphertext.serialize(), uuidCiphertextRecv.serialize())
    }

    func testServerSignatures() throws {
        let serverSecretParams = try ServerSecretParams.generate(randomness: self.TEST_ARRAY_32)
        let serverPublicParams = try serverSecretParams.getPublicParams()

        let message = self.TEST_ARRAY_32_1

        let signature = try serverSecretParams.sign(randomness: self.TEST_ARRAY_32_2, message: message)
        try serverPublicParams.verifySignature(message: message, notarySignature: signature)

        XCTAssertEqual(signature.serialize(), self.serverSignatureResult)

        var alteredMessage = message
        alteredMessage[0] ^= 1
        do {
            try serverPublicParams.verifySignature(message: alteredMessage, notarySignature: signature)
            XCTAssert(false)
        } catch SignalError.verificationFailed(_) {
            // good
        }
    }

    func testInvalidSerialized() throws {
        let ckp: [UInt8] = Array(repeating: 255, count: 289)
        do {
            _ = try GroupSecretParams(contents: ckp)
            XCTFail("should have thrown")
        } catch SignalError.invalidType(_) {
            // good
        }
    }

    func testWrongSizeSerialized() throws {
        let ckp: [UInt8] = Array(repeating: 255, count: 5)
        do {
            _ = try GroupSecretParams(contents: ckp)
            XCTFail("should have thrown")
        } catch SignalError.invalidType(_) {
            // good
        }
    }

    func testBlobEncryption() throws {
        let groupSecretParams = try GroupSecretParams.generate()
        let clientZkGroupCipher = ClientZkGroupCipher(groupSecretParams: groupSecretParams)

        let plaintext: [UInt8] = [0, 1, 2, 3, 4]
        let ciphertext = try clientZkGroupCipher.encryptBlob(plaintext: plaintext)
        let plaintext2 = try clientZkGroupCipher.decryptBlob(blobCiphertext: ciphertext)

        XCTAssertEqual(plaintext, plaintext2)
    }

    func testBlobEncryptionWithRandom() throws {
        let masterKey = try GroupMasterKey(contents: TEST_ARRAY_32_1)
        let groupSecretParams = try GroupSecretParams.deriveFromMasterKey(groupMasterKey: masterKey)
        let clientZkGroupCipher = ClientZkGroupCipher(groupSecretParams: groupSecretParams)

        let plaintext: [UInt8] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19,
        ]

        let ciphertext: [UInt8] = [
            0xDD, 0x4D, 0x03, 0x2C, 0xA9, 0xBB, 0x75, 0xA4, 0xA7, 0x85, 0x41, 0xB9, 0x0C, 0xB4, 0xE9, 0x57,
            0x43, 0xF3, 0xB0, 0xDA, 0xBF, 0xC7, 0xE1, 0x11, 0x01, 0xB0, 0x98, 0xE3, 0x4F, 0x6C, 0xF6, 0x51,
            0x39, 0x40, 0xA0, 0x4C, 0x1F, 0x20, 0xA3, 0x02, 0x69, 0x2A, 0xFD, 0xC7, 0x08, 0x7F, 0x10, 0x19,
            0x60, 0x00,
        ]

        let ciphertext257: [UInt8] = [
            0x5C, 0xB5, 0xB7, 0xBF, 0xF0, 0x6E, 0x85, 0xD9, 0x29, 0xF3, 0x51, 0x1F, 0xD1, 0x94, 0xE6, 0x38,
            0xCF, 0x32, 0xA4, 0x76, 0x63, 0x86, 0x8B, 0xC8, 0xE6, 0x4D, 0x98, 0xFB, 0x1B, 0xBE, 0x43, 0x5E,
            0xBD, 0x21, 0xC7, 0x63, 0xCE, 0x2D, 0x42, 0xE8, 0x5A, 0x1B, 0x2C, 0x16, 0x9F, 0x12, 0xF9, 0x81,
            0x8D, 0xDA, 0xDC, 0xF4, 0xB4, 0x91, 0x39, 0x8B, 0x7C, 0x5D, 0x46, 0xA2, 0x24, 0xE1, 0x58, 0x27,
            0x49, 0xF5, 0xE2, 0xA4, 0xA2, 0x29, 0x4C, 0xAA, 0xAA, 0xAB, 0x84, 0x3A, 0x1B, 0x7C, 0xF6, 0x42,
            0x6F, 0xD5, 0x43, 0xD0, 0x9F, 0xF3, 0x2A, 0x4B, 0xA5, 0xF3, 0x19, 0xCA, 0x44, 0x42, 0xB4, 0xDA,
            0x34, 0xB3, 0xE2, 0xB5, 0xB4, 0xF8, 0xA5, 0x2F, 0xDC, 0x4B, 0x48, 0x4E, 0xA8, 0x6B, 0x33, 0xDB,
            0x3E, 0xBB, 0x75, 0x8D, 0xBD, 0x96, 0x14, 0x17, 0x8F, 0x0E, 0x4E, 0x1F, 0x9B, 0x2B, 0x91, 0x4F,
            0x1E, 0x78, 0x69, 0x36, 0xB6, 0x2E, 0xD2, 0xB5, 0x8B, 0x7A, 0xE3, 0xCB, 0x3E, 0x7A, 0xE0, 0x83,
            0x5B, 0x95, 0x16, 0x95, 0x98, 0x37, 0x40, 0x66, 0x62, 0xB8, 0x5E, 0xAC, 0x74, 0x0C, 0xEF, 0x83,
            0xB6, 0x0B, 0x5A, 0xAE, 0xAA, 0xAB, 0x95, 0x64, 0x3C, 0x2B, 0xEF, 0x8C, 0xE8, 0x73, 0x58, 0xFA,
            0xBF, 0xF9, 0xD6, 0x90, 0x05, 0x2B, 0xEB, 0x9E, 0x52, 0xD0, 0xC9, 0x47, 0xE7, 0xC9, 0x86, 0xB2,
            0xF3, 0xCE, 0x3B, 0x71, 0x61, 0xCE, 0xC7, 0x2C, 0x08, 0xE2, 0xC4, 0xAD, 0xE3, 0xDE, 0xBE, 0x37,
            0x92, 0xD7, 0x36, 0xC0, 0x45, 0x7B, 0xC3, 0x52, 0xAF, 0xB8, 0xB6, 0xCA, 0xA4, 0x8A, 0x5B, 0x92,
            0xC1, 0xEC, 0x05, 0xBA, 0x80, 0x8B, 0xA8, 0xF9, 0x4C, 0x65, 0x72, 0xEB, 0xBF, 0x29, 0x81, 0x89,
            0x12, 0x34, 0x49, 0x87, 0x57, 0x3D, 0xE4, 0x19, 0xDB, 0xCC, 0x7F, 0x1E, 0xA0, 0xE4, 0xB2, 0xDD,
            0x40, 0x77, 0xB7, 0x6B, 0x38, 0x18, 0x19, 0x74, 0x7A, 0xC3, 0x32, 0xE4, 0x6F, 0xA2, 0x3A, 0xBF,
            0xC3, 0x33, 0x8E, 0x2F, 0x4B, 0x08, 0x1A, 0x8A, 0x53, 0xCB, 0xA0, 0x98, 0x8E, 0xEF, 0x11, 0x67,
            0x64, 0xD9, 0x44, 0xF1, 0xCE, 0x3F, 0x20, 0xA3, 0x02, 0x69, 0x2A, 0xFD, 0xC7, 0x08, 0x7F, 0x10,
            0x19, 0x60, 0x00,
        ]

        let ciphertext2 = try clientZkGroupCipher.encryptBlob(randomness: self.TEST_ARRAY_32_2, plaintext: plaintext)
        let plaintext2 = try clientZkGroupCipher.decryptBlob(blobCiphertext: ciphertext2)

        XCTAssertEqual(plaintext, plaintext2)
        XCTAssertEqual(ciphertext, ciphertext2)

        let plaintext257 = try clientZkGroupCipher.decryptBlob(blobCiphertext: ciphertext257)
        XCTAssertEqual(plaintext, plaintext257)
    }

    func testCreateCallLinkCredential() throws {
        let userId = Aci(fromUUID: TEST_ARRAY_16)

        let serverSecretParams = GenericServerSecretParams.generate(randomness: self.TEST_ARRAY_32)
        let serverPublicParams = serverSecretParams.getPublicParams()
        let clientSecretParams = CallLinkSecretParams.deriveFromRootKey(self.TEST_ARRAY_32_1)
        let clientPublicParams = clientSecretParams.getPublicParams()

        // Client
        let roomId = withUnsafeBytes(of: TEST_ARRAY_32_2) { Data($0) }
        let context = CreateCallLinkCredentialRequestContext.forRoomId(roomId, randomness: self.TEST_ARRAY_32_3)
        let request = context.getRequest()

        // Server
        let now = UInt64(Date().timeIntervalSince1970)
        let startOfDay = now - (now % SECONDS_PER_DAY)
        let response = request.issueCredential(userId: userId, timestamp: Date(timeIntervalSince1970: TimeInterval(startOfDay)), params: serverSecretParams, randomness: self.TEST_ARRAY_32_4)

        // Client
        let credential = try context.receive(response, userId: userId, params: serverPublicParams)
        let presentation = credential.present(roomId: roomId, userId: userId, serverParams: serverPublicParams, callLinkParams: clientSecretParams, randomness: self.TEST_ARRAY_32_5)

        // Server
        try presentation.verify(roomId: roomId, serverParams: serverSecretParams, callLinkParams: clientPublicParams)
        try presentation.verify(roomId: roomId, now: Date(timeIntervalSince1970: TimeInterval(startOfDay + SECONDS_PER_DAY)), serverParams: serverSecretParams, callLinkParams: clientPublicParams)

        XCTAssertThrowsError(try presentation.verify(roomId: roomId, now: Date(timeIntervalSince1970: TimeInterval(startOfDay + 30 * 60 * 60)), serverParams: serverSecretParams, callLinkParams: clientPublicParams))
    }

    func testCallLinkAuthCredential() throws {
        let userId = Aci(fromUUID: TEST_ARRAY_16)

        let serverSecretParams = GenericServerSecretParams.generate(randomness: self.TEST_ARRAY_32)
        let serverPublicParams = serverSecretParams.getPublicParams()
        let clientSecretParams = CallLinkSecretParams.deriveFromRootKey(self.TEST_ARRAY_32_1)
        let clientPublicParams = clientSecretParams.getPublicParams()

        // Server
        let now = UInt64(Date().timeIntervalSince1970)
        let startOfDay = now - (now % SECONDS_PER_DAY)
        let redemptionTime = Date(timeIntervalSince1970: TimeInterval(startOfDay))
        let response = CallLinkAuthCredentialResponse.issueCredential(userId: userId, redemptionTime: redemptionTime, params: serverSecretParams, randomness: self.TEST_ARRAY_32_4)

        // Client
        let credential = try response.receive(userId: userId, redemptionTime: redemptionTime, params: serverPublicParams)
        let presentation = credential.present(userId: userId, redemptionTime: redemptionTime, serverParams: serverPublicParams, callLinkParams: clientSecretParams, randomness: self.TEST_ARRAY_32_5)

        // Server
        try presentation.verify(serverParams: serverSecretParams, callLinkParams: clientPublicParams)
        try presentation.verify(now: Date(timeIntervalSince1970: TimeInterval(startOfDay + SECONDS_PER_DAY)), serverParams: serverSecretParams, callLinkParams: clientPublicParams)

        XCTAssertThrowsError(try presentation.verify(now: Date(timeIntervalSince1970: TimeInterval(startOfDay + 3 * SECONDS_PER_DAY)), serverParams: serverSecretParams, callLinkParams: clientPublicParams))

        // Client
        XCTAssertEqual(userId, try clientSecretParams.decrypt(presentation.userId))
    }

    func testDeriveProfileKey() throws {
        let expectedAccessKey: [UInt8] = [0x5A, 0x72, 0x3A, 0xCE, 0xE5, 0x2C, 0x5E, 0xA0, 0x2B, 0x92, 0xA3, 0xA3, 0x60, 0xC0, 0x95, 0x95]
        let profileKeyBytes: [UInt8] = Array(repeating: 0x02, count: 32)

        let result = try ProfileKey(contents: profileKeyBytes).deriveAccessKey()
        XCTAssertEqual(expectedAccessKey, result)
    }

    func testBackupAuthCredentialDeterministic() throws {
        // Chosen randomly
        let backupKey: [UInt8] = [
            0xF9, 0xAB, 0xBB, 0xFF, 0xA7, 0xD4, 0x24, 0x92,
            0x97, 0x65, 0xAE, 0xCC, 0x84, 0xB6, 0x04, 0x63,
            0x3C, 0x55, 0xAC, 0x1B, 0xCE, 0x82, 0xE1, 0xEE,
            0x06, 0xB7, 0x9B, 0xC9, 0xA5, 0x62, 0x93, 0x38,
        ]
        let aci = UUID(uuidString: "e74beed0-e70f-4cfd-abbb-7e3eb333bbac")!

        // These are expectations; if the contents of a credential or derivation of a backup ID
        // changes, they will need to be updated.
        let serializedBackupID: [UInt8] = [0xA2, 0x89, 0x62, 0xC7, 0xF9, 0xAC, 0x91, 0x0F, 0x66, 0xE4, 0xBC, 0xB3, 0x3F, 0x2C, 0xEF, 0x06]
        let serializedRequestCredential = Data(base64Encoded: "AISCxQa8OsFqphsQPxqtzJk5+jndpE3SJG6bfazQB399rN6N8Dv5DAwvY4N36Uj0qGf0cV5a/8rf5nkxLeVNnF3ojRSO8xaZOpKJOvWSDJIGn6EeMl2jOjx+IQg8d8M0AQ==")!

        let backupLevel = BackupLevel.free
        let credentialType = BackupCredentialType.messages

        let context = BackupAuthCredentialRequestContext.create(backupKey: backupKey, aci: aci)
        let request = context.getRequest()
        let serverSecretParams = GenericServerSecretParams.generate(randomness: self.TEST_ARRAY_32)
        let serverPublicParams = serverSecretParams.getPublicParams()
        XCTAssertEqual(
            request.serialize(),
            Array(serializedRequestCredential),
            Data(request.serialize()).base64EncodedString()
        )

        let now = UInt64(Date().timeIntervalSince1970)
        let startOfDay = now - (now % SECONDS_PER_DAY)
        let redemptionTime = Date(timeIntervalSince1970: TimeInterval(startOfDay))
        let response = request.issueCredential(timestamp: redemptionTime, backupLevel: backupLevel, type: credentialType, params: serverSecretParams, randomness: self.TEST_ARRAY_32_2)
        let credential = try context.receive(response, timestamp: redemptionTime, params: serverPublicParams)
        XCTAssertEqual(credential.backupID, serializedBackupID, credential.backupID.hexString)
        XCTAssertEqual(credential.backupLevel, backupLevel)
        XCTAssertEqual(credential.type, credentialType)
    }

    func testBackupAuthCredential() throws {
        let backupLevel = BackupLevel.free
        let credentialType = BackupCredentialType.messages

        let serverSecretParams = GenericServerSecretParams.generate(randomness: self.TEST_ARRAY_32)
        let serverPublicParams = serverSecretParams.getPublicParams()

        // Client
        let backupKey = self.TEST_ARRAY_32_1
        let aci = UUID(uuidString: "e74beed0-e70f-4cfd-abbb-7e3eb333bbac")!
        let context = BackupAuthCredentialRequestContext.create(backupKey: backupKey, aci: aci)
        let request = context.getRequest()

        // Server
        let now = UInt64(Date().timeIntervalSince1970)
        let startOfDay = now - (now % SECONDS_PER_DAY)
        let redemptionTime = Date(timeIntervalSince1970: TimeInterval(startOfDay))
        let response = request.issueCredential(timestamp: redemptionTime, backupLevel: backupLevel, type: credentialType, params: serverSecretParams, randomness: self.TEST_ARRAY_32_2)

        // Client
        let credential = try context.receive(response, timestamp: redemptionTime, params: serverPublicParams)
        XCTAssertEqual(backupLevel, credential.backupLevel)
        XCTAssertEqual(credentialType, credential.type)

        let presentation = credential.present(serverParams: serverPublicParams, randomness: self.TEST_ARRAY_32_3)

        // Server
        try presentation.verify(serverParams: serverSecretParams)
        try presentation.verify(now: Date(timeIntervalSince1970: TimeInterval(startOfDay + SECONDS_PER_DAY)), serverParams: serverSecretParams)

        // credential should be expired after 2 days
        XCTAssertThrowsError(try presentation.verify(now: Date(timeIntervalSince1970: TimeInterval(startOfDay + 1 + SECONDS_PER_DAY * 2)), serverParams: serverSecretParams))

        // future credential should be invalid
        XCTAssertThrowsError(try presentation.verify(now: Date(timeIntervalSince1970: TimeInterval(startOfDay - 1 - SECONDS_PER_DAY)), serverParams: serverSecretParams))
    }

    func testGroupSendIntegration() throws {
        let serverSecretParams = try! ServerSecretParams.generate(randomness: self.TEST_ARRAY_32)
        let serverPublicParams = try! serverSecretParams.getPublicParams()

        let aliceAci = try! Aci.parseFrom(serviceIdString: "9d0652a3-dcc3-4d11-975f-74d61598733f")
        let bobAci = try! Aci.parseFrom(serviceIdString: "6838237d-02f6-4098-b110-698253d15961")
        let eveAci = try! Aci.parseFrom(serviceIdString: "3f0f4734-e331-4434-bd4f-6d8f6ea6dcc7")
        let malloryAci = try! Aci.parseFrom(serviceIdString: "5d088142-6fd7-4dbd-af00-fdda1b3ce988")

        let masterKey = try! GroupMasterKey(contents: self.TEST_ARRAY_32_1)
        let groupSecretParams = try! GroupSecretParams.deriveFromMasterKey(groupMasterKey: masterKey)

        let aliceCiphertext = try! ClientZkGroupCipher(groupSecretParams: groupSecretParams).encrypt(aliceAci)
        let groupCiphertexts = [aliceAci, bobAci, eveAci, malloryAci].map {
            try! ClientZkGroupCipher(groupSecretParams: groupSecretParams).encrypt($0)
        }

        // SERVER
        let now = UInt64(Date().timeIntervalSince1970)
        let startOfDay = now - (now % SECONDS_PER_DAY)
        let expiration = Date(timeIntervalSince1970: TimeInterval(startOfDay + 2 * SECONDS_PER_DAY))

        // Issue endorsements
        let keyPair = GroupSendDerivedKeyPair.forExpiration(expiration, params: serverSecretParams)
        let response = GroupSendEndorsementsResponse.issue(groupMembers: groupCiphertexts, keyPair: keyPair)

        // CLIENT
        // Gets stored endorsements
        let receivedEndorsements = try response.receive(
            groupMembers: [aliceAci, bobAci, eveAci, malloryAci],
            localUser: aliceAci,
            groupParams: groupSecretParams,
            serverParams: serverPublicParams
        )

        XCTAssertThrowsError(
            try response.receive(
                groupMembers: [bobAci, eveAci, malloryAci],
                localUser: aliceAci,
                groupParams: groupSecretParams,
                serverParams: serverPublicParams
            ),
            "missing local user"
        )
        XCTAssertThrowsError(
            try response.receive(
                groupMembers: [aliceAci, eveAci, malloryAci],
                localUser: aliceAci,
                groupParams: groupSecretParams,
                serverParams: serverPublicParams
            ),
            "missing another user"
        )

        // Try receive with ciphertexts instead.
        do {
            let repeatReceivedEndorsements = try response.receive(
                groupMembers: groupCiphertexts,
                localUser: aliceCiphertext,
                serverParams: serverPublicParams
            )
            XCTAssertEqual(
                receivedEndorsements.endorsements.map { $0.serialize() },
                repeatReceivedEndorsements.endorsements.map { $0.serialize() }
            )
            XCTAssertEqual(
                receivedEndorsements.combinedEndorsement.serialize(),
                repeatReceivedEndorsements.combinedEndorsement.serialize()
            )

            XCTAssertThrowsError(
                try response.receive(
                    groupMembers: groupCiphertexts[1...],
                    localUser: aliceCiphertext,
                    serverParams: serverPublicParams
                ),
                "missing local user"
            )
            XCTAssertThrowsError(
                try response.receive(
                    groupMembers: groupCiphertexts[..<3],
                    localUser: aliceCiphertext,
                    serverParams: serverPublicParams
                ),
                "missing another user"
            )
        }

        let combinedToken = receivedEndorsements.combinedEndorsement.toToken(groupParams: groupSecretParams)
        let fullCombinedToken = combinedToken.toFullToken(expiration: response.expiration)

        // SERVER
        // Verify token
        let verifyKey = GroupSendDerivedKeyPair.forExpiration(fullCombinedToken.expiration, params: serverSecretParams)

        try fullCombinedToken.verify(
            userIds: [bobAci, eveAci, malloryAci],
            keyPair: verifyKey
        )
        try fullCombinedToken.verify(
            userIds: [bobAci, eveAci, malloryAci],
            now: Date(timeIntervalSinceNow: 60 * 60),
            keyPair: verifyKey
        )

        XCTAssertThrowsError(
            try fullCombinedToken.verify(
                userIds: [aliceAci, bobAci, eveAci, malloryAci],
                keyPair: verifyKey
            ),
            "included extra user"
        )
        XCTAssertThrowsError(
            try fullCombinedToken.verify(
                userIds: [eveAci, malloryAci],
                keyPair: verifyKey
            ),
            "missing user"
        )

        XCTAssertThrowsError(
            try fullCombinedToken.verify(
                userIds: [bobAci, eveAci, malloryAci],
                now: expiration.addingTimeInterval(1),
                keyPair: verifyKey
            ),
            "expired"
        )

        // Excluding a user
        do {
            // CLIENT
            let everybodyButMallory = receivedEndorsements
                .combinedEndorsement
                .byRemoving(receivedEndorsements.endorsements[3])
            let fullEverybodyButMalloryToken = everybodyButMallory
                .toFullToken(groupParams: groupSecretParams, expiration: response.expiration)

            // SERVER
            let everybodyButMalloryKey = GroupSendDerivedKeyPair.forExpiration(fullEverybodyButMalloryToken.expiration, params: serverSecretParams)

            try fullEverybodyButMalloryToken.verify(
                userIds: [bobAci, eveAci],
                keyPair: everybodyButMalloryKey
            )
        }

        // Custom combine
        do {
            // CLIENT
            let bobAndEve = GroupSendEndorsement.combine(receivedEndorsements.endorsements[1...2])
            let fullBobAndEveToken = bobAndEve.toFullToken(groupParams: groupSecretParams, expiration: response.expiration)

            // SERVER
            let bobAndEveKey = GroupSendDerivedKeyPair.forExpiration(fullBobAndEveToken.expiration, params: serverSecretParams)

            try fullBobAndEveToken.verify(userIds: [bobAci, eveAci], keyPair: bobAndEveKey)
        }

        // Single-user
        do {
            // CLIENT
            let bobEndorsement = receivedEndorsements.endorsements[1]
            let fullBobToken = bobEndorsement.toFullToken(groupParams: groupSecretParams, expiration: response.expiration)

            // SERVER
            let bobKey = GroupSendDerivedKeyPair.forExpiration(fullBobToken.expiration, params: serverSecretParams)

            try fullBobToken.verify(userIds: [bobAci], keyPair: bobKey)
        }
    }

    func test1000PersonGroup() throws {
        // SERVER
        // Generate keys
        let serverSecretParams =
            try ServerSecretParams.generate(randomness: self.TEST_ARRAY_32)
        let serverPublicParams = try serverSecretParams.getPublicParams()

        // CLIENT
        // Generate keys
        let masterKey = try GroupMasterKey(contents: TEST_ARRAY_32_1)
        let groupSecretParams = try GroupSecretParams.deriveFromMasterKey(groupMasterKey: masterKey)

        // Set up group state
        let members = (0..<1000).map { _ in Aci(fromUUID: UUID()) }

        let cipher = ClientZkGroupCipher(groupSecretParams: groupSecretParams)
        let encryptedMembers = try members.map { try cipher.encrypt($0) }

        // SERVER
        // Issue endorsements
        let now = UInt64(Date().timeIntervalSince1970)
        let startOfDay = now - (now % SECONDS_PER_DAY)
        let expiration = Date(timeIntervalSince1970: TimeInterval(startOfDay + 2 * SECONDS_PER_DAY))

        let keyPair = GroupSendDerivedKeyPair.forExpiration(expiration, params: serverSecretParams)
        let response = GroupSendEndorsementsResponse.issue(groupMembers: encryptedMembers, keyPair: keyPair)

        // CLIENT
        // Gets stored endorsements
        // Just don't crash (this did crash on a lower-end Android phone once).
        _ = try response.receive(groupMembers: members, localUser: members[0], groupParams: groupSecretParams, serverParams: serverPublicParams)
        _ = try response.receive(groupMembers: encryptedMembers, localUser: encryptedMembers[0], serverParams: serverPublicParams)
    }

    func test1PersonGroup() throws {
        // SERVER
        // Generate keys
        let serverSecretParams =
            try ServerSecretParams.generate(randomness: self.TEST_ARRAY_32)
        let serverPublicParams = try serverSecretParams.getPublicParams()

        // CLIENT
        // Generate keys
        let masterKey = try GroupMasterKey(contents: TEST_ARRAY_32_1)
        let groupSecretParams = try GroupSecretParams.deriveFromMasterKey(groupMasterKey: masterKey)

        // Set up group state
        let member = Aci(fromUUID: UUID())

        let cipher = ClientZkGroupCipher(groupSecretParams: groupSecretParams)
        let encryptedMember = try cipher.encrypt(member)

        // SERVER
        // Issue endorsements
        let now = UInt64(Date().timeIntervalSince1970)
        let startOfDay = now - (now % SECONDS_PER_DAY)
        let expiration = Date(timeIntervalSince1970: TimeInterval(startOfDay + 2 * SECONDS_PER_DAY))

        let keyPair = GroupSendDerivedKeyPair.forExpiration(expiration, params: serverSecretParams)
        let response = GroupSendEndorsementsResponse.issue(groupMembers: [encryptedMember], keyPair: keyPair)

        // CLIENT
        // Gets stored endorsements
        // Just don't crash.
        _ = try response.receive(groupMembers: [member], localUser: member, groupParams: groupSecretParams, serverParams: serverPublicParams)
        _ = try response.receive(groupMembers: [encryptedMember], localUser: encryptedMember, serverParams: serverPublicParams)
    }
}
