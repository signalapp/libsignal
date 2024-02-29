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
        XCTAssertEqual(error.errorMessage, "HMAC doesn't match")
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

  func testInputThrowsAfter() {
    let bytes = readResource(forName: "new_account.binproto.encrypted")
    let makeStream = { ThrowsAfterInputStream(inner: SignalInputStreamAdapter(bytes), readBeforeThrow: UInt64(bytes.count) - 1) }
    XCTAssertThrowsError(
      try validateMessageBackup(key: MessageBackupKey.testKey(), length: UInt64(bytes.count), makeStream: makeStream)
    ) { error in
      if error is TestIoError {} else { XCTFail("\(error)") }
    }
  }

  static func validateBackup<Input>(bytes: Input)  throws -> MessageBackupUnknownFields
  where Input: Collection<UInt8> {
    try validateMessageBackup(key: MessageBackupKey.testKey(), length: UInt64(bytes.count), makeStream: { SignalInputStreamAdapter(bytes) })
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
