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

#if !os(iOS) || targetEnvironment(simulator)
    func testComparableBackup() throws {
        let bytes = readResource(forName: "canonical-backup.binproto")
        let backup = try ComparableBackup(purpose: .remoteBackup, length: UInt64(bytes.count), stream: SignalInputStreamAdapter(bytes))
        let comparableString = backup.comparableString()

        let expected = String(data: readResource(forName: "canonical-backup.expected.json"), encoding: .utf8)!
        XCTAssertEqual(comparableString, expected)
    }
#endif

    static func validateBackup(bytes: some Collection<UInt8>) throws -> MessageBackupUnknownFields {
        try validateMessageBackup(key: MessageBackupKey.testKey(), purpose: .remoteBackup, length: UInt64(bytes.count), makeStream: { SignalInputStreamAdapter(bytes) })
    }
}

extension MessageBackupKey {
    public static func testKey() -> MessageBackupKey {
        let masterKey = Array(repeating: Character("M").asciiValue!, count: 32)
        let uuid: uuid_t = (
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11
        )
        let aci = Aci(fromUUID: UUID(uuid: uuid))
        return try! MessageBackupKey(masterKey: masterKey, aci: aci)
    }
}
