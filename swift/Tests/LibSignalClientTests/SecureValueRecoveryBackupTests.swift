//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi
import XCTest

@testable import LibSignalClient

final class SecureValueRecoveryBackupTests: TestCaseBase {
    private let testAci = try! Aci.parseFrom(serviceIdString: "e74beed0-e70f-4cfd-abbb-7e3eb333bbac")
    private let testBackupKey = BackupKey.generateRandom()
    private let testInvalidSecretData = Data("invalid secret data".utf8)
    private lazy var net = Net(env: .staging, userAgent: "test", buildVariant: .production)
    private lazy var testAuth: Auth = {
        let process = ProcessInfo.processInfo

        // The OTP-secret-based Auth isn't available in device builds.
        #if !os(iOS) || targetEnvironment(simulator)
        if let enclaveSecret = process.environment["LIBSIGNAL_TESTING_SVRB_ENCLAVE_SECRET"] {
            let username = testBackupKey.deriveBackupId(aci: testAci).toHex()
            return try! Auth(
                username: username,
                enclaveSecret: enclaveSecret
            )
        }
        #endif

        return Auth(
            username: process.environment["LIBSIGNAL_TESTING_SVRB_USERNAME"] ?? "",
            password: process.environment["LIBSIGNAL_TESTING_SVRB_PASSWORD"] ?? ""
        )
    }()
    private lazy var svrB = net.svrB(auth: testAuth)

    private var currentTestIsNonHermetic = false

    override func nonHermeticTest() throws {
        try super.nonHermeticTest()
        currentTestIsNonHermetic = true
    }

    override func tearDown() async throws {
        if currentTestIsNonHermetic {
            do {
                // As a best effort, try to clean up after ourselves
                // so we don't use up a ton of space on the server.
                try await svrB.remove()
            } catch {
                print(error)
            }
        }
    }

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
            XCTAssertEqual(message, "Invalid data from previous backup")
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
