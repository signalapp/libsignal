//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import XCTest
import LibSignalClient

class IncrementalMacTests: TestCaseBase {
    private let TEST_KEY = Data(base64Encoded: "qDSBRX7+zGmtE0LiHZwCl/cd679ckwS0wbLkM8Gnj5g=")!
    private let TEST_INPUT = ["this is a test", " input to the incremental ", "mac stream"].map { Data($0.utf8) }
    private let TEST_DIGEST = Array(Data(base64Encoded: "hIkvcGAOVJ+3KHlmep2WonPxRLaY/571p2BipWBhqQmIT22fQpGKnkdu1RjErI9xS9M/BFFSrgSYd/09Gw2yWg==")!)
    private let CHUNK_SIZE = SizeChoice.bytes(32)

    func testIncrementalDigestCreation() throws {
        let mac = try IncrementalMacContext(key: TEST_KEY, chunkSize: CHUNK_SIZE)
        for d in TEST_INPUT {
            try mac.update(d)
        }
        let digest = try mac.finalize()
        XCTAssertEqual(TEST_DIGEST, digest)
    }

    func testIncrementalValidationSuccess() throws {
        let mac = try ValidatingMacContext(key: TEST_KEY, chunkSize: CHUNK_SIZE, expectingDigest: TEST_DIGEST)
        for d in TEST_INPUT {
            XCTAssertNoThrow { try mac.update(d) }
        }
        XCTAssertNoThrow { try mac.finalize() }
    }

    func testIncrementalValidationFailure() throws {
        var corruptInput = TEST_INPUT
        corruptInput[2][0] ^= 0xff

        let mac = try ValidatingMacContext(key: TEST_KEY, chunkSize: CHUNK_SIZE, expectingDigest: TEST_DIGEST)
        for d in corruptInput {
            try mac.update(d)
        }
        do {
            try mac.finalize()
            XCTFail("Should have failed")
        } catch SignalError.verificationFailed {
        } catch {
            XCTFail("Unexpected error thrown")
        }
    }
}
