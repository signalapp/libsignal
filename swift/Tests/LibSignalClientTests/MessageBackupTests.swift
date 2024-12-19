//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

class MessageBackupTests: TestCaseBase {
    func testValidInput() throws {
        let validBackupContents = readResource(forName: "new_account.binproto.encrypted")

        let outcome = try Self.validateBackup(bytes: validBackupContents)
        XCTAssertEqual(outcome.fields, [])

        // Verify that the key can also be created from a backup ID and produce the same result.
        _ = try validateMessageBackup(
            key: MessageBackupKey.testKeyFromBackupId(),
            purpose: .remoteBackup,
            length: UInt64(validBackupContents.count),
            makeStream: { SignalInputStreamAdapter(validBackupContents) }
        )
    }

    func testMessageBackupKeyParts() {
        let testKey = MessageBackupKey.testKey()
        // Just check some basic expectations.
        XCTAssertEqual(32, testKey.hmacKey.count)
        XCTAssertEqual(32, testKey.aesKey.count)
        XCTAssertNotEqual(testKey.hmacKey, testKey.aesKey)
    }

    func testInvalidInput() throws {
        // Start with a valid file, then overwrite some bytes
        var bytes = readResource(forName: "new_account.binproto.encrypted")
        bytes.replaceSubrange(0..<32, with: Array(repeating: 0, count: 32))
        // Validation failed, so this should throw.
        XCTAssertThrowsError(try Self.validateBackup(bytes: bytes)) { error in
            if let error = error as? MessageBackupValidationError {
                XCTAssert(error.errorMessage.starts(with: "HMAC doesn't match"), "\(error.errorMessage)")
            } else {
                XCTFail("\(error)")
            }
        }
    }

    func testEmptyInput() throws {
        XCTAssertThrowsError(try Self.validateBackup(bytes: [])) { error in
            if let error = error as? MessageBackupValidationError {
                XCTAssertEqual(error.errorMessage, "not enough bytes for an HMAC")
            } else {
                XCTFail("\(error)")
            }
        }
    }

    func testInputFactoryThrows() {
        struct TestFactoryError: Error {}

        XCTAssertThrowsError(
            try validateMessageBackup(
                key: MessageBackupKey.testKey(),
                purpose: .remoteBackup,
                length: 4242
            ) { throw TestFactoryError() }
        ) { error in
            if error is TestFactoryError {} else { XCTFail("\(error)") }
        }
    }

    func testInputThrowsAfter() {
        let bytes = readResource(forName: "new_account.binproto.encrypted")
        let makeStream = { ThrowsAfterInputStream(inner: SignalInputStreamAdapter(bytes), readBeforeThrow: UInt64(bytes.count) - 1) }
        XCTAssertThrowsError(
            try validateMessageBackup(key: MessageBackupKey.testKey(), purpose: .remoteBackup, length: UInt64(bytes.count), makeStream: makeStream)
        ) { error in
            if error is TestIoError {} else { XCTFail("\(error)") }
        }
    }

    func testOnlineValidatorInvalidBackupInfo() throws {
        XCTAssertThrowsError(try OnlineBackupValidator(backupInfo: [], purpose: .remoteBackup))
    }

    // The following payload was generated via protoscope.
    // % protoscope -s | base64
    // The fields are described by Backup.proto.
    //
    // 1: 1
    // 2: 1731715200000
    // 3: {`00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff`}
    private let VALID_BACKUP_INFO: Data = .init(base64Encoded: "CAEQgOiTkrMyGiAAESIzRFVmd4iZqrvM3e7/ABEiM0RVZneImaq7zN3u/w==")!

    func testOnlineValidatorInvalidFrame() throws {
        let backup = try OnlineBackupValidator(backupInfo: VALID_BACKUP_INFO, purpose: .remoteBackup)
        XCTAssertThrowsError(try backup.addFrame([]))
    }

    func testOnlineValidatorInvalidFinalize() throws {
        let backup = try OnlineBackupValidator(backupInfo: VALID_BACKUP_INFO, purpose: .remoteBackup)
        XCTAssertThrowsError(try backup.finalize())
    }

    func testAccountEntropyPoolValidity() {
        XCTAssertFalse(AccountEntropyPool.isValid("invalid key"))
        XCTAssertTrue(
            AccountEntropyPool.isValid(
                "0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr"))
    }

#if !os(iOS) || targetEnvironment(simulator)
    func testComparableBackup() throws {
        let bytes = readResource(forName: "canonical-backup.binproto")
        let backup = try ComparableBackup(purpose: .remoteBackup, length: UInt64(bytes.count), stream: SignalInputStreamAdapter(bytes))
        let comparableString = backup.comparableString()

        let expected = String(data: readResource(forName: "canonical-backup.expected.json"), encoding: .utf8)!
        XCTAssertEqual(comparableString, expected)
    }

    func testOnlineValidation() throws {
        var bytes = readResource(forName: "canonical-backup.binproto")

        let backupInfoLength = Int(bytes[0])
        XCTAssertLessThan(backupInfoLength, 0x80, "single-byte varint")
        let backupInfo = bytes.dropFirst(1).prefix(backupInfoLength)
        XCTAssertEqual(backupInfo.count, backupInfoLength, "unexpected EOF")
        let backup = try OnlineBackupValidator(backupInfo: backupInfo, purpose: .remoteBackup)
        bytes = bytes[backupInfo.endIndex...]

        while var frameLength = bytes.first.map({ Int($0) }) {
            bytes = bytes.dropFirst()
            // Tiny varint parser, only supports two bytes.
            if frameLength >= 0x80 {
                let secondByte = Int(bytes.first!)
                XCTAssertLessThan(secondByte, 0x80, "at most a two-byte varint")
                frameLength -= 0x80
                frameLength |= secondByte << 7
                bytes = bytes.dropFirst()
            }
            let frame = bytes.prefix(frameLength)
            XCTAssertEqual(frame.count, frameLength, "unexpected EOF")
            try backup.addFrame(frame)
            bytes = bytes[frame.endIndex...]
        }

        try backup.finalize()
    }
#endif

    static func validateBackup(bytes: some Collection<UInt8>) throws -> MessageBackupUnknownFields {
        try validateMessageBackup(key: MessageBackupKey.testKey(), purpose: .remoteBackup, length: UInt64(bytes.count), makeStream: { SignalInputStreamAdapter(bytes) })
    }
}

extension MessageBackupKey {
    public static func testKey() -> MessageBackupKey {
        let accountEntropy = String(repeating: "m", count: 64)
        let uuid: uuid_t = (
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
        )
        let aci = Aci(fromUUID: UUID(uuid: uuid))
        return try! MessageBackupKey(accountEntropy: accountEntropy, aci: aci)
    }

    public static func testKeyFromBackupId() -> MessageBackupKey {
        let accountEntropy = String(repeating: "m", count: 64)
        let uuid: uuid_t = (
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
        )
        let aci = Aci(fromUUID: UUID(uuid: uuid))

        let backupKey = try! hkdf(
            outputLength: 32,
            inputKeyMaterial: Array(accountEntropy.utf8),
            salt: [],
            info: Array("20240801_SIGNAL_BACKUP_KEY".utf8)
        )
        let backupId = try! hkdf(
            outputLength: 16,
            inputKeyMaterial: backupKey,
            salt: [],
            info: Array("20241024_SIGNAL_BACKUP_ID:".utf8) + aci.serviceIdBinary
        )

        return try! MessageBackupKey(backupKey: BackupKey(contents: backupKey), backupId: backupId)
    }
}
