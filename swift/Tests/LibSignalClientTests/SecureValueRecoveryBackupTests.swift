//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient
import SignalFfi
import XCTest

final class SecureValueRecoveryBackupTests: TestCaseBase {
    private let testBackupKey = BackupKey.generateRandom()
    private let testInvalidSecretData = Data("invalid secret data".utf8)
    private lazy var net = Net(env: .staging, userAgent: "test")
    private let testAuth = Auth(
        username: ProcessInfo.processInfo.environment["LIBSIGNAL_TESTING_SVRB_USERNAME"] ?? "",
        password: ProcessInfo.processInfo.environment["LIBSIGNAL_TESTING_SVRB_PASSWORD"] ?? ""
    )
    private lazy var svrB = net.svrB(auth: testAuth)

    private func assertValidToken(_ token: BackupForwardSecrecyToken) {
        let tokenBytes = token.serialize()
        XCTAssertEqual(tokenBytes.count, BackupForwardSecrecyToken.SIZE)

        // Test round-trip serialization
        XCTAssertNoThrow(try BackupForwardSecrecyToken(contents: tokenBytes))
    }

    func testPrepareBackupWithInvalidPreviousSecretDataThrowsInvalidArgument() async throws {
        await assertThrowsErrorAsync {
            try await svrB.store(
                backupKey: testBackupKey,
                previousSecretData: testInvalidSecretData
            )
        } errorHandler: { error in
            guard let signalError = error as? SignalError,
                case .invalidArgument(let message) = signalError
            else {
                XCTFail("Expected SignalError.invalidArgument, got \(error)")
                return
            }
            XCTAssertEqual(message, "SVR error: Invalid data from previous backup")
        }
    }

    func testFullBackupFlowWithPreviousSecretData() async throws {
        try self.nonHermeticTest()
        if testAuth.username.isEmpty || testAuth.password.isEmpty {
            throw XCTSkip("requires LIBSIGNAL_TESTING_SVRB_USERNAME and LIBSIGNAL_TESTING_SVRB_PASSWORD")
        }

        // First backup without previous data
        let initialSecretData = svrB.createNewBackupChain(backupKey: testBackupKey)
        let firstResponse = try await svrB.store(backupKey: testBackupKey, previousSecretData: initialSecretData)
        let firstToken = firstResponse.forwardSecrecyToken
        assertValidToken(firstToken)
        let firstSecretData = firstResponse.nextBackupSecretData
        XCTAssertFalse(firstSecretData.isEmpty)
        XCTAssertFalse(firstResponse.metadata.isEmpty)

        // Restore first backup
        let restoredFirst = try await svrB.restore(
            backupKey: testBackupKey,
            metadata: firstResponse.metadata
        )
        XCTAssertEqual(firstToken.serialize(), restoredFirst.forwardSecrecyToken.serialize())

        // Second backup with previous secret data
        let secondResponse = try await svrB.store(backupKey: testBackupKey, previousSecretData: firstSecretData)
        let secondToken = secondResponse.forwardSecrecyToken
        assertValidToken(secondToken)
        XCTAssertFalse(secondResponse.nextBackupSecretData.isEmpty)
        XCTAssertFalse(secondResponse.metadata.isEmpty)

        // Restore second backup
        let restoredSecond = try await svrB.restore(
            backupKey: testBackupKey,
            metadata: secondResponse.metadata
        )
        XCTAssertEqual(secondToken.serialize(), restoredSecond.forwardSecrecyToken.serialize())

        // The tokens should be different between backups
        XCTAssertNotEqual(firstToken.serialize(), secondToken.serialize())
    }
}
