//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest
import SignalClient

class CryptoTests: TestCaseBase {
    func generateAesKey() -> [UInt8] {
        var key = Array(repeating: UInt8(0), count: 32)
        let result = SecRandomCopyBytes(kSecRandomDefault, key.count, &key)
        precondition(result == errSecSuccess)
        return key
    }

    func testAesGcmSiv() {
        let ptext: [UInt8] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        let expected_ctext: [UInt8] = [0x1d, 0xe2, 0x29, 0x67, 0x23, 0x7a, 0x81, 0x32, 0x91, 0x21, 0x3f, 0x26, 0x7e, 0x3b, 0x45, 0x2f, 0x02, 0xd0, 0x1a, 0xe3, 0x3e, 0x4e, 0xc8, 0x54]
        let ad: [UInt8] = [0x01]
        let key: [UInt8] = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        let nonce: [UInt8] = [0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

        let gcm_siv = try! Aes256GcmSiv(key: key)

        let ctext = try! gcm_siv.encrypt(ptext, nonce: nonce, associatedData: ad)
        XCTAssertEqual(ctext, expected_ctext)

        let recovered = try! gcm_siv.decrypt(ctext, nonce: nonce, associatedData: ad)
        XCTAssertEqual(recovered, ptext)

        XCTAssertThrowsError(try gcm_siv.decrypt(ptext, nonce: nonce, associatedData: ad))
        XCTAssertThrowsError(try gcm_siv.decrypt(ctext, nonce: ad, associatedData: nonce))
    }

    func testAesGcm() {
        let plainTextData = Data("Super🔥secret🔥test🔥data🏁🏁".utf8)
        XCTAssertEqual(39, plainTextData.count)

        let key = generateAesKey()
        let encryptedParts = try! Aes256GcmEncryptedData.encrypt(plainTextData, key: key)
        let encryptedData = encryptedParts.concatenate()
        XCTAssertEqual(Aes256GcmEncryptedData.nonceLength + plainTextData.count + Aes256GcmEncryptedData.authenticationTagLength, encryptedData.count)

        let splitParts = try! Aes256GcmEncryptedData(concatenated: encryptedData)
        XCTAssertEqual(encryptedParts.nonce, splitParts.nonce)
        XCTAssertEqual(encryptedParts.ciphertext, splitParts.ciphertext)
        XCTAssertEqual(encryptedParts.authenticationTag, splitParts.authenticationTag)

        let decryptedData = try! splitParts.decrypt(key: key)
        XCTAssertEqual(39, decryptedData.count)
        XCTAssertEqual(plainTextData, decryptedData)

        var encryptedWithBadTag = encryptedData
        encryptedWithBadTag[encryptedWithBadTag.count - 1] ^= 0xff
        XCTAssertThrowsError(try Aes256GcmEncryptedData(concatenated: encryptedWithBadTag).decrypt(key: key)) {
            guard case SignalError.invalidMessage(_) = $0 else {
                XCTFail("wrong error: \($0)")
                return
            }
        }
    }

    func testAesGcmKat() {
        let key: [UInt8] = [0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08]
        let plaintext = Data([0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39])
        let expectedCiphertext = Data([0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9, 0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38, 0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62])
        let expectedTag = Data([0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b])
        let nonce: [UInt8] = [0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88]
        let ad: [UInt8] = [0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2]

        let gcmEnc = try! Aes256GcmEncryption(key: key, nonce: nonce, associatedData: ad)
        var ciphertext = plaintext
        try! gcmEnc.encrypt(&ciphertext)
        let tag = try! gcmEnc.computeTag()
        XCTAssertEqual(ciphertext, expectedCiphertext)
        XCTAssertEqual(tag, expectedTag)

        let gcmDec = try! Aes256GcmDecryption(key: key, nonce: nonce, associatedData: ad)
        var decrypted = ciphertext
        try! gcmDec.decrypt(&decrypted)
        XCTAssertEqual(decrypted, plaintext)
        XCTAssert(try! gcmDec.verifyTag(tag))

        let gcmEnc2 = try! Aes256GcmEncryption(key: key, nonce: nonce, associatedData: ad)
        var ciphertextSplit = plaintext
        try! gcmEnc2.encrypt(&ciphertextSplit[..<1])
        try! gcmEnc2.encrypt(&ciphertextSplit[1...])
        let tag2 = try! gcmEnc2.computeTag()
        XCTAssertEqual(ciphertextSplit, expectedCiphertext)
        XCTAssertEqual(tag2, expectedTag)

        let gcmDec2 = try! Aes256GcmDecryption(key: key, nonce: nonce, associatedData: ad)
        var decryptedSplit = ciphertext
        try! gcmDec2.decrypt(&decryptedSplit[..<1])
        try! gcmDec2.decrypt(&decryptedSplit[1...])
        XCTAssertEqual(decryptedSplit, plaintext)
        XCTAssert(try! gcmDec2.verifyTag(tag))
    }

    static var allTests: [(String, (CryptoTests) -> () throws -> Void)] {
        return [
            ("testAesGcmSiv", testAesGcmSiv),
            ("testAesGcm", testAesGcm),
            ("testAesGcmKat", testAesGcmKat),
        ]
    }
}
