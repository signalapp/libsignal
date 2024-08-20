//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import LibSignalClient
import XCTest

class SessionRecordTests: TestCaseBase {
    func testBadPreKeyRecords() {
        XCTAssertThrowsError(try PreKeyRecord(bytes: [0]))
        XCTAssertThrowsError(try SignedPreKeyRecord(bytes: [0]))
        XCTAssertThrowsError(try KyberPreKeyRecord(bytes: [0]))

        // The keys in records are lazily parsed, which means malformed keys aren't caught right away.
        // The following payloads were generated via protoscope:
        // % protoscope -s | base64
        // The fields are described in storage.proto in the libsignal-protocol crate.
        do {
            // 1: 42
            // 2: {}
            // 3: {}
            let record = try! PreKeyRecord(bytes: Data(base64Encoded: "CCoSABoA")!)
            XCTAssertThrowsError(try record.publicKey())
            XCTAssertThrowsError(try record.privateKey())
        }

        do {
            // 1: 42
            // 2: {}
            // 3: {}
            // 4: {}
            // 5: 0i64
            let record = try! SignedPreKeyRecord(bytes: Data(base64Encoded: "CCoSABoAIgApAAAAAAAAAAA=")!)
            XCTAssertThrowsError(try record.publicKey())
            XCTAssertThrowsError(try record.privateKey())
        }

        do {
            // 1: 42
            // 2: {}
            // 3: {}
            // 4: {}
            // 5: 0i64
            let record = try! KyberPreKeyRecord(bytes: Data(base64Encoded: "CCoSABoAIgApAAAAAAAAAAA=")!)
            XCTAssertThrowsError(try record.publicKey())
            XCTAssertThrowsError(try record.secretKey())
            XCTAssertThrowsError(try record.keyPair())
        }
    }
}
