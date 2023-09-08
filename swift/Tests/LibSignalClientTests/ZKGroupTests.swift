//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest
import LibSignalClient

private let SECONDS_PER_DAY: UInt64 = 24 * 60 * 60

class ZKGroupTests: TestCaseBase {

  let TEST_ARRAY_16: UUID         = UUID(uuid: (0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f))

  let TEST_ARRAY_16_1: UUID       = UUID(uuid: (0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73))

  let TEST_ARRAY_32: Randomness   = Randomness((0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                              0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                                              0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f))

  let TEST_ARRAY_32_1: [UInt8]    = [0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73,
                                  0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83]

  let TEST_ARRAY_32_2: Randomness = Randomness((0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
                                                0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
                                                0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
                                                0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7))

  let TEST_ARRAY_32_3: Randomness = Randomness((
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
      28, 29, 30, 31, 32))

  let TEST_ARRAY_32_4: Randomness = Randomness((
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
    28, 29, 30, 31, 32, 33))

  let TEST_ARRAY_32_5: Randomness = Randomness((0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                                0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
                                                0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
                                                0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22))

  let authPresentationResult: [UInt8] = [
    0x01, 0x32, 0x2f, 0x91, 0x00, 0xde, 0x07, 0x34, 0x55, 0x0a, 0x81, 0xdc, 0x81, 0x72, 0x4a, 0x81,
    0xdb, 0xd3, 0xb1, 0xb4, 0x3d, 0xbc, 0x1d, 0x55, 0x2d, 0x53, 0x45, 0x59, 0x11, 0xc2, 0x77, 0x2f,
    0x34, 0xa6, 0x35, 0x6c, 0xa1, 0x7c, 0x6d, 0x34, 0xd8, 0x58, 0x39, 0x14, 0x56, 0xaf, 0x55, 0xd0,
    0xef, 0x84, 0x1f, 0xbe, 0x1f, 0xa8, 0xc4, 0xee, 0x81, 0x0f, 0x21, 0xe0, 0xbb, 0x9f, 0x4a, 0xce,
    0x4c, 0x5c, 0x48, 0xc7, 0x2e, 0xbb, 0xeb, 0x2c, 0xcd, 0xa5, 0xf7, 0xaa, 0x49, 0xae, 0xe6, 0xbc,
    0x00, 0x51, 0xcd, 0xde, 0x16, 0x6e, 0x0f, 0x8c, 0x5f, 0x1f, 0xeb, 0xd5, 0x3a, 0x44, 0x37, 0xc5,
    0x70, 0xee, 0x1a, 0xa2, 0x23, 0xf5, 0xeb, 0x93, 0x7d, 0xb9, 0x8f, 0x34, 0xe3, 0x65, 0x3d, 0x85,
    0xec, 0x16, 0x3f, 0x39, 0x84, 0x72, 0x22, 0xa2, 0xde, 0xc4, 0x23, 0x5e, 0xa4, 0x1c, 0x47, 0xbb,
    0x62, 0x02, 0x8a, 0xae, 0x30, 0x94, 0x58, 0x57, 0xee, 0x77, 0x66, 0x30, 0x79, 0xbc, 0xc4, 0x92,
    0x3d, 0x14, 0xa4, 0x3a, 0xd4, 0xf6, 0xbc, 0x33, 0x71, 0x50, 0x46, 0xf7, 0xbd, 0xe5, 0x27, 0x15,
    0x37, 0x5c, 0xa9, 0xf8, 0x9b, 0xe0, 0xe6, 0x30, 0xd4, 0xbd, 0xaa, 0x21, 0x11, 0x56, 0xd0, 0x30,
    0x67, 0x23, 0xf5, 0x43, 0xb0, 0x6f, 0x5e, 0x99, 0x84, 0x47, 0xb9, 0x62, 0xc8, 0xe9, 0x72, 0x9b,
    0x4c, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x74, 0xd0, 0xea, 0xe8, 0xe4, 0x31, 0x1a,
    0x6a, 0xe3, 0xd2, 0x97, 0x0e, 0xf1, 0x98, 0xc3, 0x98, 0x11, 0x04, 0x62, 0xbe, 0x47, 0xdd, 0x2f,
    0x26, 0xe6, 0x55, 0x92, 0x09, 0xef, 0x6c, 0xc2, 0x00, 0x01, 0xa0, 0x5a, 0x0b, 0x31, 0x9a, 0x17,
    0x2d, 0xbe, 0xb2, 0x29, 0x3c, 0xc1, 0xe0, 0xe1, 0x91, 0xce, 0xfb, 0x23, 0xe2, 0x4c, 0xf0, 0xd6,
    0xb4, 0xb5, 0x37, 0x3a, 0x30, 0x04, 0x4b, 0xe1, 0x0c, 0xb0, 0x33, 0x67, 0x4d, 0x63, 0x1e, 0x17,
    0xdf, 0xce, 0x09, 0x39, 0x8f, 0x23, 0x4e, 0x9d, 0x62, 0xe1, 0x18, 0xa6, 0x07, 0x7c, 0xae, 0xa0,
    0xef, 0x8b, 0xf6, 0x7d, 0x7d, 0x72, 0x3d, 0xb7, 0x0f, 0xec, 0xf2, 0x09, 0x8f, 0xa0, 0x41, 0x31,
    0x7b, 0x7b, 0xe9, 0xfd, 0xbb, 0x68, 0xb0, 0xf2, 0x5f, 0x5c, 0x47, 0x9d, 0x68, 0xbd, 0x91, 0x7f,
    0xc6, 0xf1, 0x87, 0xc5, 0xbf, 0x7a, 0x58, 0x91, 0x02, 0x31, 0x92, 0x1f, 0xc4, 0x35, 0x65, 0x23,
    0x24, 0x66, 0x32, 0x5c, 0x03, 0x92, 0x12, 0x36, 0x2b, 0x6d, 0x12, 0x03, 0xcc, 0xae, 0xdf, 0x83,
    0x1d, 0xc7, 0xf9, 0x06, 0x0d, 0xca, 0xaf, 0xfa, 0x02, 0x62, 0x40, 0x42, 0x17, 0x1f, 0x5f, 0x0e,
    0x78, 0x0b, 0x9f, 0x74, 0xcf, 0xa8, 0x8a, 0x14, 0x7f, 0x3f, 0x1c, 0x08, 0x2f, 0x9c, 0xa8, 0x63,
    0x8a, 0xf1, 0x78, 0x8e, 0x78, 0x99, 0xcb, 0xae, 0x0c, 0x76, 0x5d, 0xe9, 0xdf, 0x4c, 0xfa, 0x54,
    0x87, 0xf3, 0x60, 0xe2, 0x9e, 0x99, 0x34, 0x3e, 0x91, 0x81, 0x1b, 0xae, 0xc3, 0x31, 0xc4, 0x68,
    0x09, 0x85, 0xe6, 0x08, 0xca, 0x5d, 0x40, 0x8e, 0x21, 0x72, 0x5c, 0x6a, 0xa1, 0xb6, 0x1d, 0x5a,
    0x8b, 0x48, 0xd7, 0x5f, 0x4a, 0xaa, 0x9a, 0x3c, 0xbe, 0x88, 0xd3, 0xe0, 0xf1, 0xa5, 0x43, 0x19,
    0x08, 0x1f, 0x77, 0xc7, 0x2c, 0x8f, 0x52, 0x54, 0x74, 0x40, 0xe2, 0x01, 0x00]

  let serverSignatureResult: [UInt8] = [ 0x87, 0xd3, 0x54, 0x56, 0x4d, 0x35,
  0xef, 0x91, 0xed, 0xba, 0x85, 0x1e, 0x08, 0x15, 0x61, 0x2e, 0x86, 0x4c, 0x22,
  0x7a, 0x04, 0x71, 0xd5, 0x0c, 0x27, 0x06, 0x98, 0x60, 0x44, 0x06, 0xd0, 0x03,
  0xa5, 0x54, 0x73, 0xf5, 0x76, 0xcf, 0x24, 0x1f, 0xc6, 0xb4, 0x1c, 0x6b, 0x16,
  0xe5, 0xe6, 0x3b, 0x33, 0x3c, 0x02, 0xfe, 0x4a, 0x33, 0x85, 0x80, 0x22, 0xfd,
  0xd7, 0xa4, 0xab, 0x36, 0x7b, 0x06]

  func testAuthIntegration() throws {
    let aci: Aci               = Aci(fromUUID: TEST_ARRAY_16)
    let redemptionTime: UInt32 = 123456

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    let serverSecretParams = try ServerSecretParams.generate(randomness: TEST_ARRAY_32)
    let serverPublicParams = try serverSecretParams.getPublicParams()
    let serverZkAuth       = ServerZkAuthOperations(serverSecretParams: serverSecretParams)

    // CLIENT
    let masterKey         = try GroupMasterKey(contents: TEST_ARRAY_32_1)
    let groupSecretParams = try GroupSecretParams.deriveFromMasterKey(groupMasterKey: masterKey)

    XCTAssertEqual((try groupSecretParams.getMasterKey()).serialize(), masterKey.serialize())

    let groupPublicParams = try groupSecretParams.getPublicParams()

    // SERVER
    // Issue credential
    let authCredentialResponse = try serverZkAuth.issueAuthCredential(randomness: TEST_ARRAY_32_2, aci: aci, redemptionTime: redemptionTime)

    // CLIENT
    // Receive credential
    let clientZkAuthCipher  = ClientZkAuthOperations(serverPublicParams: serverPublicParams)
    let clientZkGroupCipher = ClientZkGroupCipher(groupSecretParams: groupSecretParams)
    let authCredential      = try clientZkAuthCipher.receiveAuthCredential(aci: aci, redemptionTime: redemptionTime, authCredentialResponse: authCredentialResponse)

    // Create and decrypt user entry
    let uuidCiphertext = try clientZkGroupCipher.encrypt(aci)
    let plaintext      = try clientZkGroupCipher.decrypt(uuidCiphertext)
    XCTAssertEqual(aci, plaintext)

    // Create presentation
    let presentation = try clientZkAuthCipher.createAuthCredentialPresentation(randomness: TEST_ARRAY_32_5, groupSecretParams: groupSecretParams, authCredential: authCredential)

    // Verify presentation
    let uuidCiphertextRecv = try presentation.getUuidCiphertext()
    XCTAssertEqual(uuidCiphertext.serialize(), uuidCiphertextRecv.serialize())
    XCTAssertNil(try presentation.getPniCiphertext())
    XCTAssertEqual(try presentation.getRedemptionTime(),
                   Date(timeIntervalSince1970: TimeInterval(redemptionTime) * TimeInterval(SECONDS_PER_DAY)))
    try serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams: groupPublicParams, authCredentialPresentation: presentation, now: Date(timeIntervalSince1970: TimeInterval(redemptionTime) * TimeInterval(SECONDS_PER_DAY)))

    XCTAssertEqual(presentation.serialize(), authPresentationResult)
  }

  func testAuthWithPniIntegration() throws {
    let aci: Aci               = Aci(fromUUID: TEST_ARRAY_16)
    let pni: Pni               = Pni(fromUUID: TEST_ARRAY_16_1)
    let redemptionTime: UInt64 = 123456 * SECONDS_PER_DAY

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    let serverSecretParams = try ServerSecretParams.generate(randomness: TEST_ARRAY_32)
    let serverPublicParams = try serverSecretParams.getPublicParams()
    let serverZkAuth       = ServerZkAuthOperations(serverSecretParams: serverSecretParams)

    // CLIENT
    let masterKey         = try GroupMasterKey(contents: TEST_ARRAY_32_1)
    let groupSecretParams = try GroupSecretParams.deriveFromMasterKey(groupMasterKey: masterKey)

    XCTAssertEqual((try groupSecretParams.getMasterKey()).serialize(), masterKey.serialize())

    let groupPublicParams = try groupSecretParams.getPublicParams()

    // SERVER
    // Issue credential
    let authCredentialResponse = try serverZkAuth.issueAuthCredentialWithPniAsServiceId(randomness: TEST_ARRAY_32_2, aci: aci, pni: pni, redemptionTime: redemptionTime)

    // CLIENT
    // Receive credential
    let clientZkAuthCipher  = ClientZkAuthOperations(serverPublicParams: serverPublicParams)
    let clientZkGroupCipher = ClientZkGroupCipher(groupSecretParams: groupSecretParams)
    let authCredential      = try clientZkAuthCipher.receiveAuthCredentialWithPniAsServiceId(aci: aci, pni: pni, redemptionTime: redemptionTime, authCredentialResponse: authCredentialResponse)
    XCTAssertThrowsError(try clientZkAuthCipher.receiveAuthCredentialWithPniAsAci(aci: aci, pni: pni, redemptionTime: redemptionTime, authCredentialResponse: authCredentialResponse))

    // Create and decrypt user entry
    let aciCiphertext = try clientZkGroupCipher.encrypt(aci)
    let aciPlaintext  = try clientZkGroupCipher.decrypt(aciCiphertext)
    XCTAssertEqual(aci, aciPlaintext)
    let pniCiphertext = try clientZkGroupCipher.encrypt(pni)
    let pniPlaintext  = try clientZkGroupCipher.decrypt(pniCiphertext)
    XCTAssertEqual(pni, pniPlaintext)

    // Create presentation
    let presentation = try clientZkAuthCipher.createAuthCredentialPresentation(randomness: TEST_ARRAY_32_5, groupSecretParams: groupSecretParams, authCredential: authCredential)

    // Verify presentation
    let uuidCiphertextRecv = try presentation.getUuidCiphertext()
    XCTAssertEqual(aciCiphertext.serialize(), uuidCiphertextRecv.serialize())
    XCTAssertEqual(pniCiphertext.serialize(), try presentation.getPniCiphertext()?.serialize())
    XCTAssertEqual(try presentation.getRedemptionTime(), Date(timeIntervalSince1970: TimeInterval(redemptionTime)))
    try serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams: groupPublicParams, authCredentialPresentation: presentation, now: Date(timeIntervalSince1970: TimeInterval(redemptionTime)))
  }

  func testAuthWithPniAsAciIntegration() throws {
    let aci: Aci               = Aci(fromUUID: TEST_ARRAY_16)
    let pni: Pni               = Pni(fromUUID: TEST_ARRAY_16_1)
    let redemptionTime: UInt64 = 123456 * SECONDS_PER_DAY

    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    let serverSecretParams = try ServerSecretParams.generate(randomness: TEST_ARRAY_32)
    let serverPublicParams = try serverSecretParams.getPublicParams()
    let serverZkAuth       = ServerZkAuthOperations(serverSecretParams: serverSecretParams)

    // CLIENT
    let masterKey         = try GroupMasterKey(contents: TEST_ARRAY_32_1)
    let groupSecretParams = try GroupSecretParams.deriveFromMasterKey(groupMasterKey: masterKey)

    XCTAssertEqual((try groupSecretParams.getMasterKey()).serialize(), masterKey.serialize())

    let groupPublicParams = try groupSecretParams.getPublicParams()

    // SERVER
    // Issue credential
    let authCredentialResponse = try serverZkAuth.issueAuthCredentialWithPniAsAci(randomness: TEST_ARRAY_32_2, aci: aci, pni: pni, redemptionTime: redemptionTime)

    // CLIENT
    // Receive credential
    let clientZkAuthCipher  = ClientZkAuthOperations(serverPublicParams: serverPublicParams)
    let clientZkGroupCipher = ClientZkGroupCipher(groupSecretParams: groupSecretParams)
    let authCredential      = try clientZkAuthCipher.receiveAuthCredentialWithPniAsAci(aci: aci, pni: pni, redemptionTime: redemptionTime, authCredentialResponse: authCredentialResponse)
    XCTAssertThrowsError(try clientZkAuthCipher.receiveAuthCredentialWithPniAsServiceId(aci: aci, pni: pni, redemptionTime: redemptionTime, authCredentialResponse: authCredentialResponse))

    // Create and decrypt user entry
    let aciCiphertext = try clientZkGroupCipher.encrypt(aci)
    let aciPlaintext  = try clientZkGroupCipher.decrypt(aciCiphertext)
    XCTAssertEqual(aci, aciPlaintext)
    let pniAsAci      = Aci(fromUUID: pni.rawUUID)
    let pniCiphertext = try clientZkGroupCipher.encrypt(pniAsAci)
    let pniPlaintext  = try clientZkGroupCipher.decrypt(pniCiphertext)
    XCTAssertEqual(pniAsAci, pniPlaintext)

    // Create presentation
    let presentation = try clientZkAuthCipher.createAuthCredentialPresentation(randomness: TEST_ARRAY_32_5, groupSecretParams: groupSecretParams, authCredential: authCredential)

    // Verify presentation
    let uuidCiphertextRecv = try presentation.getUuidCiphertext()
    XCTAssertEqual(aciCiphertext.serialize(), uuidCiphertextRecv.serialize())
    XCTAssertEqual(pniCiphertext.serialize(), try presentation.getPniCiphertext()?.serialize())
    XCTAssertEqual(try presentation.getRedemptionTime(), Date(timeIntervalSince1970: TimeInterval(redemptionTime)))
    try serverZkAuth.verifyAuthCredentialPresentation(groupPublicParams: groupPublicParams, authCredentialPresentation: presentation, now: Date(timeIntervalSince1970: TimeInterval(redemptionTime)))
  }

  func testExpiringProfileKeyIntegration() throws {
    let userId: Aci             = Aci(fromUUID: TEST_ARRAY_16)
    // Generate keys (client's are per-group, server's are not)
    // ---

    // SERVER
    let serverSecretParams = try ServerSecretParams.generate(randomness: TEST_ARRAY_32)
    let serverPublicParams = try serverSecretParams.getPublicParams()
    let serverZkProfile    = ServerZkProfileOperations(serverSecretParams: serverSecretParams)

    // CLIENT
    let masterKey         = try GroupMasterKey(contents: TEST_ARRAY_32_1)
    let groupSecretParams = try GroupSecretParams.deriveFromMasterKey(groupMasterKey: masterKey)

    XCTAssertEqual(try groupSecretParams.getMasterKey().serialize(), masterKey.serialize())

    let groupPublicParams = try groupSecretParams.getPublicParams()
    let clientZkProfileCipher = ClientZkProfileOperations(serverPublicParams: serverPublicParams)

    let profileKey  = try ProfileKey(contents: TEST_ARRAY_32_1)
    let profileKeyCommitment = try profileKey.getCommitment(userId: userId)

    // Create context and request
    let context = try clientZkProfileCipher.createProfileKeyCredentialRequestContext(randomness: TEST_ARRAY_32_3, userId: userId, profileKey: profileKey)
    let request = try context.getRequest()

    // SERVER
    let now = UInt64(Date().timeIntervalSince1970)
    let startOfDay = now - (now % SECONDS_PER_DAY)
    let expiration = startOfDay + 5 * SECONDS_PER_DAY
    let response = try serverZkProfile.issueExpiringProfileKeyCredential(randomness: TEST_ARRAY_32_4, profileKeyCredentialRequest: request, userId: userId, profileKeyCommitment: profileKeyCommitment, expiration: expiration)

    // CLIENT
    // Gets stored profile credential
    let clientZkGroupCipher  = ClientZkGroupCipher(groupSecretParams: groupSecretParams)
    let profileKeyCredential = try clientZkProfileCipher.receiveExpiringProfileKeyCredential(profileKeyCredentialRequestContext: context, profileKeyCredentialResponse: response)

    // Create encrypted UID and profile key
    let uuidCiphertext = try clientZkGroupCipher.encrypt(userId)
    let plaintext      = try clientZkGroupCipher.decrypt(uuidCiphertext)
    XCTAssertEqual(plaintext, userId)

    let profileKeyCiphertext   = try clientZkGroupCipher.encryptProfileKey(profileKey: profileKey, userId: userId)
    let decryptedProfileKey    = try clientZkGroupCipher.decryptProfileKey(profileKeyCiphertext: profileKeyCiphertext, userId: userId)
    XCTAssertEqual(profileKey.serialize(), decryptedProfileKey.serialize())

    XCTAssertEqual(Date(timeIntervalSince1970: TimeInterval(expiration)), profileKeyCredential.expirationTime)

    let presentation = try clientZkProfileCipher.createProfileKeyCredentialPresentation(randomness: TEST_ARRAY_32_5, groupSecretParams: groupSecretParams, profileKeyCredential: profileKeyCredential)

    // Verify presentation
    try serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams: groupPublicParams, profileKeyCredentialPresentation: presentation)
    try serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams: groupPublicParams, profileKeyCredentialPresentation: presentation, now: Date(timeIntervalSince1970: TimeInterval(expiration - 5)))
    XCTAssertThrowsError(try serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams: groupPublicParams, profileKeyCredentialPresentation: presentation, now: Date(timeIntervalSince1970: TimeInterval(expiration))))
    XCTAssertThrowsError(try serverZkProfile.verifyProfileKeyCredentialPresentation(groupPublicParams: groupPublicParams, profileKeyCredentialPresentation: presentation, now: Date(timeIntervalSince1970: TimeInterval(expiration + 5))))

    let uuidCiphertextRecv = try presentation.getUuidCiphertext()
    XCTAssertEqual(uuidCiphertext.serialize(), uuidCiphertextRecv.serialize())
  }

  func testServerSignatures() throws {
    let serverSecretParams = try ServerSecretParams.generate(randomness: TEST_ARRAY_32)
    let serverPublicParams = try serverSecretParams.getPublicParams()

    let message = TEST_ARRAY_32_1

    let signature = try serverSecretParams.sign(randomness: TEST_ARRAY_32_2, message: message)
    try serverPublicParams.verifySignature(message: message, notarySignature: signature)

    XCTAssertEqual(signature.serialize(), serverSignatureResult)

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
    let masterKey           = try GroupMasterKey(contents: TEST_ARRAY_32_1)
    let groupSecretParams   = try GroupSecretParams.deriveFromMasterKey(groupMasterKey: masterKey)
    let clientZkGroupCipher = ClientZkGroupCipher(groupSecretParams: groupSecretParams)

    let plaintext: [UInt8]   = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19]

    let ciphertext: [UInt8] = [ 0xdd, 0x4d, 0x03, 0x2c, 0xa9, 0xbb, 0x75, 0xa4,
    0xa7, 0x85, 0x41, 0xb9, 0x0c, 0xb4, 0xe9, 0x57, 0x43, 0xf3, 0xb0, 0xda,
    0xbf, 0xc7, 0xe1, 0x11, 0x01, 0xb0, 0x98, 0xe3, 0x4f, 0x6c, 0xf6, 0x51,
    0x39, 0x40, 0xa0, 0x4c, 0x1f, 0x20, 0xa3, 0x02, 0x69, 0x2a, 0xfd, 0xc7,
    0x08, 0x7f, 0x10, 0x19, 0x60, 0x00]

    let ciphertext257: [UInt8] = [ 0x5c, 0xb5, 0xb7, 0xbf, 0xf0, 0x6e, 0x85, 0xd9,
    0x29, 0xf3, 0x51, 0x1f, 0xd1, 0x94, 0xe6, 0x38, 0xcf, 0x32, 0xa4, 0x76,
    0x63, 0x86, 0x8b, 0xc8, 0xe6, 0x4d, 0x98, 0xfb, 0x1b, 0xbe, 0x43, 0x5e,
    0xbd, 0x21, 0xc7, 0x63, 0xce, 0x2d, 0x42, 0xe8, 0x5a, 0x1b, 0x2c, 0x16,
    0x9f, 0x12, 0xf9, 0x81, 0x8d, 0xda, 0xdc, 0xf4, 0xb4, 0x91, 0x39, 0x8b,
    0x7c, 0x5d, 0x46, 0xa2, 0x24, 0xe1, 0x58, 0x27, 0x49, 0xf5, 0xe2, 0xa4,
    0xa2, 0x29, 0x4c, 0xaa, 0xaa, 0xab, 0x84, 0x3a, 0x1b, 0x7c, 0xf6, 0x42,
    0x6f, 0xd5, 0x43, 0xd0, 0x9f, 0xf3, 0x2a, 0x4b, 0xa5, 0xf3, 0x19, 0xca,
    0x44, 0x42, 0xb4, 0xda, 0x34, 0xb3, 0xe2, 0xb5, 0xb4, 0xf8, 0xa5, 0x2f,
    0xdc, 0x4b, 0x48, 0x4e, 0xa8, 0x6b, 0x33, 0xdb, 0x3e, 0xbb, 0x75, 0x8d,
    0xbd, 0x96, 0x14, 0x17, 0x8f, 0x0e, 0x4e, 0x1f, 0x9b, 0x2b, 0x91, 0x4f,
    0x1e, 0x78, 0x69, 0x36, 0xb6, 0x2e, 0xd2, 0xb5, 0x8b, 0x7a, 0xe3, 0xcb,
    0x3e, 0x7a, 0xe0, 0x83, 0x5b, 0x95, 0x16, 0x95, 0x98, 0x37, 0x40, 0x66,
    0x62, 0xb8, 0x5e, 0xac, 0x74, 0x0c, 0xef, 0x83, 0xb6, 0x0b, 0x5a, 0xae,
    0xaa, 0xab, 0x95, 0x64, 0x3c, 0x2b, 0xef, 0x8c, 0xe8, 0x73, 0x58, 0xfa,
    0xbf, 0xf9, 0xd6, 0x90, 0x05, 0x2b, 0xeb, 0x9e, 0x52, 0xd0, 0xc9, 0x47,
    0xe7, 0xc9, 0x86, 0xb2, 0xf3, 0xce, 0x3b, 0x71, 0x61, 0xce, 0xc7, 0x2c,
    0x08, 0xe2, 0xc4, 0xad, 0xe3, 0xde, 0xbe, 0x37, 0x92, 0xd7, 0x36, 0xc0,
    0x45, 0x7b, 0xc3, 0x52, 0xaf, 0xb8, 0xb6, 0xca, 0xa4, 0x8a, 0x5b, 0x92,
    0xc1, 0xec, 0x05, 0xba, 0x80, 0x8b, 0xa8, 0xf9, 0x4c, 0x65, 0x72, 0xeb,
    0xbf, 0x29, 0x81, 0x89, 0x12, 0x34, 0x49, 0x87, 0x57, 0x3d, 0xe4, 0x19,
    0xdb, 0xcc, 0x7f, 0x1e, 0xa0, 0xe4, 0xb2, 0xdd, 0x40, 0x77, 0xb7, 0x6b,
    0x38, 0x18, 0x19, 0x74, 0x7a, 0xc3, 0x32, 0xe4, 0x6f, 0xa2, 0x3a, 0xbf,
    0xc3, 0x33, 0x8e, 0x2f, 0x4b, 0x08, 0x1a, 0x8a, 0x53, 0xcb, 0xa0, 0x98,
    0x8e, 0xef, 0x11, 0x67, 0x64, 0xd9, 0x44, 0xf1, 0xce, 0x3f, 0x20, 0xa3,
    0x02, 0x69, 0x2a, 0xfd, 0xc7, 0x08, 0x7f, 0x10, 0x19, 0x60, 0x00 ]

    let ciphertext2 = try clientZkGroupCipher.encryptBlob(randomness: TEST_ARRAY_32_2, plaintext: plaintext)
    let plaintext2 = try clientZkGroupCipher.decryptBlob(blobCiphertext: ciphertext2)

    XCTAssertEqual(plaintext, plaintext2)
    XCTAssertEqual(ciphertext, ciphertext2)

    let plaintext257 = try clientZkGroupCipher.decryptBlob(blobCiphertext: ciphertext257)
    XCTAssertEqual(plaintext, plaintext257)
  }

  func testCreateCallLinkCredential() throws {
    let userId = Aci(fromUUID: TEST_ARRAY_16)

    let serverSecretParams = GenericServerSecretParams.generate(randomness: TEST_ARRAY_32)
    let serverPublicParams = serverSecretParams.getPublicParams()
    let clientSecretParams = CallLinkSecretParams.deriveFromRootKey(TEST_ARRAY_32_1)
    let clientPublicParams = clientSecretParams.getPublicParams()

    // Client
    let roomId = withUnsafeBytes(of: TEST_ARRAY_32_2) { Data($0) }
    let context = CreateCallLinkCredentialRequestContext.forRoomId(roomId, randomness: TEST_ARRAY_32_3)
    let request = context.getRequest()

    // Server
    let now = UInt64(Date().timeIntervalSince1970)
    let startOfDay = now - (now % SECONDS_PER_DAY)
    let response = request.issueCredential(userId: userId, timestamp: Date(timeIntervalSince1970: TimeInterval(startOfDay)), params: serverSecretParams, randomness: TEST_ARRAY_32_4)

    // Client
    let credential = try context.receive(response, userId: userId, params: serverPublicParams)
    let presentation = credential.present(roomId: roomId, userId: userId, serverParams: serverPublicParams, callLinkParams: clientSecretParams, randomness: TEST_ARRAY_32_5)

    // Server
    try presentation.verify(roomId: roomId, serverParams: serverSecretParams, callLinkParams: clientPublicParams)
    try presentation.verify(roomId: roomId, now: Date(timeIntervalSince1970: TimeInterval(startOfDay + SECONDS_PER_DAY)), serverParams: serverSecretParams, callLinkParams: clientPublicParams)

    XCTAssertThrowsError(try presentation.verify(roomId: roomId, now: Date(timeIntervalSince1970: TimeInterval(startOfDay + 30 * 60 * 60)), serverParams: serverSecretParams, callLinkParams: clientPublicParams))
  }

  func testCallLinkAuthCredential() throws {
    let userId = Aci(fromUUID: TEST_ARRAY_16)

    let serverSecretParams = GenericServerSecretParams.generate(randomness: TEST_ARRAY_32)
    let serverPublicParams = serverSecretParams.getPublicParams()
    let clientSecretParams = CallLinkSecretParams.deriveFromRootKey(TEST_ARRAY_32_1)
    let clientPublicParams = clientSecretParams.getPublicParams()

    // Server
    let now = UInt64(Date().timeIntervalSince1970)
    let startOfDay = now - (now % SECONDS_PER_DAY)
    let redemptionTime = Date(timeIntervalSince1970: TimeInterval(startOfDay))
    let response = CallLinkAuthCredentialResponse.issueCredential(userId: userId, redemptionTime: redemptionTime, params: serverSecretParams, randomness: TEST_ARRAY_32_4)

    // Client
    let credential = try response.receive(userId: userId, redemptionTime: redemptionTime, params: serverPublicParams)
    let presentation = credential.present(userId: userId, redemptionTime: redemptionTime, serverParams: serverPublicParams, callLinkParams: clientSecretParams, randomness: TEST_ARRAY_32_5)

    // Server
    try presentation.verify(serverParams: serverSecretParams, callLinkParams: clientPublicParams)
    try presentation.verify(now: Date(timeIntervalSince1970: TimeInterval(startOfDay + SECONDS_PER_DAY)), serverParams: serverSecretParams, callLinkParams: clientPublicParams)

    XCTAssertThrowsError(try presentation.verify(now: Date(timeIntervalSince1970: TimeInterval(startOfDay + 3 * SECONDS_PER_DAY)), serverParams: serverSecretParams, callLinkParams: clientPublicParams))

    // Client
    XCTAssertEqual(userId, try clientSecretParams.decrypt(presentation.userId))
  }

  func testDeriveProfileKey() throws {
    let expectedAccessKey: [UInt8] = [0x5a, 0x72, 0x3a, 0xce, 0xe5, 0x2c, 0x5e, 0xa0, 0x2b, 0x92, 0xa3, 0xa3, 0x60, 0xc0, 0x95, 0x95]
    let profileKeyBytes: [UInt8] = Array(repeating: 0x02, count: 32)

    let result = try ProfileKey(contents: profileKeyBytes).deriveAccessKey()
    XCTAssertEqual(expectedAccessKey, result)
  }
}
