//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient
import XCTest

class IncrementalMacTests: TestCaseBase {
    private let TEST_KEY = Data(base64Encoded: "qDSBRX7+zGmtE0LiHZwCl/cd679ckwS0wbLkM8Gnj5g=")!
    private let TEST_INPUT = ["this is a test", " input to the incremental ", "mac stream"].map { Data($0.utf8) }
    private let TEST_DIGEST = Array(Data(base64Encoded: "hIkvcGAOVJ+3KHlmep2WonPxRLaY/571p2BipWBhqQmIT22fQpGKnkdu1RjErI9xS9M/BFFSrgSYd/09Gw2yWg==")!)
    private let CHUNK_SIZE = SizeChoice.bytes(32)

    func testIncrementalDigestCreation() throws {
        let mac = try IncrementalMacContext(key: TEST_KEY, chunkSize: CHUNK_SIZE)
        for d in self.TEST_INPUT {
            try mac.update(d)
        }
        let digest = try mac.finalize()
        XCTAssertEqual(self.TEST_DIGEST, digest)
    }

    func testIncrementalDigestChunkSizeAbsolute() throws {
        let mac = try IncrementalMacContext(key: TEST_KEY, chunkSize: CHUNK_SIZE)
        XCTAssertEqual(32, mac.chunkSizeInBytes)
    }

    func testIncrementalDigestChunkSizeInferred() throws {
        let mac = try IncrementalMacContext(key: TEST_KEY, chunkSize: .chunkOf(42))
        XCTAssertEqual(65536, mac.chunkSizeInBytes)
    }

    func testIncrementalValidationSuccess() throws {
        let mac = try ValidatingMacContext(key: TEST_KEY, chunkSize: CHUNK_SIZE, expectingDigest: TEST_DIGEST)
        for d in self.TEST_INPUT {
            _ = try mac.update(d)
        }
        _ = try mac.finalize()
    }

    func testNoBytesCanBeConsumedWithoutValidation() throws {
        var corruptInput = self.TEST_INPUT
        corruptInput[0][1] ^= 0xFF

        let mac = try ValidatingMacContext(key: TEST_KEY, chunkSize: CHUNK_SIZE, expectingDigest: TEST_DIGEST)
        XCTAssertEqual(0, try mac.update(corruptInput[0]))
        do {
            _ = try mac.update(corruptInput[1])
            XCTFail("Should have failed")
        } catch SignalError.verificationFailed {
        } catch {
            XCTFail("Unexpected error thrown")
        }
    }

    func testIncrementalValidationFailureInFinalize() throws {
        var corruptInput = self.TEST_INPUT
        corruptInput[2][0] ^= 0xFF

        let mac = try ValidatingMacContext(key: TEST_KEY, chunkSize: CHUNK_SIZE, expectingDigest: TEST_DIGEST)
        XCTAssertEqual(0, try mac.update(corruptInput[0]))
        XCTAssertEqual(32, try mac.update(corruptInput[1]))
        XCTAssertEqual(0, try mac.update(corruptInput[2]))
        do {
            _ = try mac.finalize()
            XCTFail("Should have failed")
        } catch SignalError.verificationFailed {
        } catch {
            XCTFail("Unexpected error thrown")
        }
    }
}
