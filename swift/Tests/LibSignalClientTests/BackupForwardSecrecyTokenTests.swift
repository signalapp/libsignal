//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient
import XCTest

final class BackupForwardSecrecyTokenTests: TestCaseBase {
    func testValidTokenCreation() throws {
        let validBytes = Data(repeating: 0x42, count: 32)
        let token = try BackupForwardSecrecyToken(contents: validBytes)

        XCTAssertNotNil(token)
        XCTAssertEqual(token.serialize().count, 32)

        let retrievedBytes = token.serialize()
        XCTAssertEqual(retrievedBytes, validBytes)
    }

    func testInvalidTokenCreationTooShort() {
        let invalidBytes = Data(repeating: 0x42, count: 31)

        XCTAssertThrowsError(try BackupForwardSecrecyToken(contents: invalidBytes)) { error in
            guard let signalError = error as? SignalError,
                case .invalidType(let message) = signalError
            else {
                XCTFail("Expected SignalError.invalidType, got \(error)")
                return
            }
            XCTAssertTrue(message.contains("32 bytes"))
            XCTAssertTrue(message.contains("31 bytes"))
        }
    }

    func testInvalidTokenCreationTooLong() {
        let invalidBytes = Data(repeating: 0x42, count: 33)

        XCTAssertThrowsError(try BackupForwardSecrecyToken(contents: invalidBytes)) { error in
            guard let signalError = error as? SignalError,
                case .invalidType(let message) = signalError
            else {
                XCTFail("Expected SignalError.invalidType, got \(error)")
                return
            }
            XCTAssertTrue(message.contains("32 bytes"))
            XCTAssertTrue(message.contains("33 bytes"))
        }
    }

    func testRoundTripSerialization() throws {
        var originalBytes = Data(count: 32)
        for i in 0..<32 {
            originalBytes[i] = UInt8(i % 256)
        }

        let token = try BackupForwardSecrecyToken(contents: originalBytes)

        let serialized = token.serialize()
        let reconstructedToken = try BackupForwardSecrecyToken(contents: serialized)

        XCTAssertNotNil(reconstructedToken)
        XCTAssertEqual(reconstructedToken.serialize().count, 32)

        let reconstructedBytes = reconstructedToken.serialize()
        XCTAssertEqual(reconstructedBytes, originalBytes)
    }

    func testSizeConstant() {
        XCTAssertEqual(BackupForwardSecrecyToken.SIZE, 32)
    }
}
