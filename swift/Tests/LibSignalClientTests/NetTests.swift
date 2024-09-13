//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

import Foundation
@testable import LibSignalClient
import SignalFfi
import XCTest

let userAgent: String = "test"

final class NetTests: XCTestCase {
    func testCdsiLookupResultConversion() async throws {
        let ACI_UUID = "9d0652a3-dcc3-4d11-975f-74d61598733f"
        let PNI_UUID = "796abedb-ca4e-4f18-8803-1fde5b921f9f"

        let aci = Aci(fromUUID: UUID(uuidString: ACI_UUID)!)
        let pni = Pni(fromUUID: UUID(uuidString: PNI_UUID)!)

        let asyncContext = TokioAsyncContext()

        let output: SignalFfiCdsiLookupResponse = try await asyncContext.invokeAsyncFunction { promise, asyncContext in
            signal_testing_cdsi_lookup_response_convert(promise, asyncContext)
        }
        XCTAssertEqual(output.debug_permits_used, 123)

        let entryList = LookupResponseEntryList(owned: output.entries)
        let expected = [SignalFfiCdsiLookupResponseEntry(
            e164: 18_005_551_011,
            aci, pni
        ), SignalFfiCdsiLookupResponseEntry(
            e164: 18_005_551_012,
            nil,
            pni
        )]

        XCTAssertEqual(expected, Array(entryList))
    }

    func testCdsiLookupErrorConversion() async throws {
        let failWithError = {
            try checkError(signal_testing_cdsi_lookup_error_convert($0))
            XCTFail("should have failed")
        }
        do {
            try failWithError("Protocol")
        } catch SignalError.networkProtocolError(let message) {
            XCTAssertEqual(message, "Protocol error: protocol error after establishing a connection")
        }
        do {
            try failWithError("AttestationDataError")
        } catch SignalError.invalidAttestationData(let message) {
            XCTAssertEqual(message, "SGX operation failed: attestation data invalid: fake reason")
        }
        do {
            try failWithError("InvalidResponse")
        } catch SignalError.networkProtocolError(let message) {
            XCTAssertEqual(message, "Protocol error: invalid response received from the server")
        }
        do {
            try failWithError("RetryAfter42Seconds")
        } catch SignalError.rateLimitedError(retryAfter: 42, let message) {
            XCTAssertEqual(message, "Rate limited; try again after 42s")
        }
        do {
            try failWithError("InvalidToken")
        } catch SignalError.cdsiInvalidToken(let message) {
            XCTAssertEqual(message, "CDSI request token was invalid")
        }
        do {
            try failWithError("InvalidArgument")
        } catch SignalError.invalidArgument(let message) {
            XCTAssertEqual(message, "invalid argument: request was invalid: fake reason")
        }
        do {
            try failWithError("Parse")
        } catch SignalError.networkProtocolError(let message) {
            XCTAssertEqual(message, "Protocol error: failed to parse the response from the server")
        }
        do {
            try failWithError("ConnectDnsFailed")
        } catch SignalError.ioError(let message) {
            XCTAssertEqual(message, "IO error: DNS lookup failed")
        }
        do {
            try failWithError("WebSocketIdleTooLong")
        } catch SignalError.webSocketError(let message) {
            XCTAssertEqual(message, "WebSocket error: channel was idle for too long")
        }
        do {
            try failWithError("ConnectionTimedOut")
        } catch SignalError.connectionTimeoutError(let message) {
            XCTAssertEqual(message, "Connect timed out")
        }
        do {
            try failWithError("ServerCrashed")
        } catch SignalError.networkProtocolError(let message) {
            XCTAssertEqual(message, "Protocol error: server error: crashed")
        }
    }

    func testCdsiLookupCompilation() async throws {
        try throwSkipForCompileOnlyTest()

        let auth = Auth(username: "username", password: "password")
        let request = try CdsiLookupRequest(
            e164s: [],
            prevE164s: [],
            acisAndAccessKeys: [],
            token: nil,
            returnAcisWithoutUaks: false
        )
        let net = Net(env: .staging, userAgent: userAgent)

        let lookup = try await net.cdsiLookup(auth: auth, request: request)
        let response = try await lookup.complete()
        for entry in response.entries {
            _ = entry.aci
            _ = entry.pni
            _ = entry.e164
        }
    }

    func testNetworkChangeEvent() throws {
        // There's no feedback from this, we're just making sure it doesn't normally crash or throw.
        let net = Net(env: .staging, userAgent: userAgent)
        try net.networkDidChange()
    }
}

final class Svr3Tests: TestCaseBase {
    struct State {
        var auth: Auth
        var net: Net
    }

    private var state: State? = nil

    private let storedSecret = randomBytes(32)

    func getEnclaveSecret() throws -> String {
        guard let enclaveSecret = ProcessInfo.processInfo.environment["LIBSIGNAL_TESTING_ENCLAVE_SECRET"] else {
            throw XCTSkip("requires LIBSIGNAL_TESTING_ENCLAVE_SECRET")
        }
        return enclaveSecret
    }

    override func setUpWithError() throws {
        let username = randomBytes(16).hexString
        let net = Net(env: .staging, userAgent: userAgent)
        let auth = try Auth(username: username, enclaveSecret: self.getEnclaveSecret())
        self.state = State(auth: auth, net: net)
    }

    override func tearDown() async throws {
        guard self.state != nil else {
            return
        }
        do {
            try await self.state!.net.svr3.remove(auth: self.state!.auth)
            self.state = nil
        } catch {}
    }

    func testBackupAndRestore() async throws {
        let tries = UInt32(10)

        let shareSet = try await state!.net.svr3.backup(
            self.storedSecret,
            password: "password",
            maxTries: tries,
            auth: self.state!.auth
        )

        let restoredSecret = try await state!.net.svr3.restore(
            password: "password",
            shareSet: shareSet,
            auth: self.state!.auth
        )
        XCTAssertEqual(restoredSecret.value, self.storedSecret)
        XCTAssertEqual(restoredSecret.triesRemaining, tries - 1)
    }

    func testRestoreAfterRemove() async throws {
        let tries = UInt32(10)

        let shareSet = try await state!.net.svr3.backup(
            self.storedSecret,
            password: "password",
            maxTries: tries,
            auth: self.state!.auth
        )
        try await self.state!.net.svr3.remove(auth: self.state!.auth)
        do {
            _ = try await self.state!.net.svr3.restore(
                password: "password",
                shareSet: shareSet,
                auth: self.state!.auth
            )
            XCTFail("Should have thrown")
        } catch SignalError.svrDataMissing(_) {
            // Success!
        } catch {
            XCTFail("Unexpected exception: '\(error)'")
        }
    }

    func testRemoveSomethingThatNeverWas() async throws {
        try await self.state!.net.svr3.remove(auth: self.state!.auth)
    }

    func testInvalidPassword() async throws {
        let tries = UInt32(10)

        let shareSet = try await state!.net.svr3.backup(
            self.storedSecret,
            password: "password",
            maxTries: tries,
            auth: self.state!.auth
        )

        do {
            _ = try await self.state!.net.svr3.restore(
                password: "invalid password",
                shareSet: shareSet,
                auth: self.state!.auth
            )
            XCTFail("Should have thrown")
        } catch SignalError.svrRestoreFailed(let triesRemaining, _) {
            // Success!
            XCTAssertEqual(triesRemaining, tries - 1)
        } catch {
            XCTFail("Unexpected exception: '\(error)'")
        }
    }

    func testCorruptedShareSet() async throws {
        var shareSet = try await state!.net.svr3.backup(
            self.storedSecret,
            password: "password",
            maxTries: 10,
            auth: self.state!.auth
        )
        // Invert a byte somewhere inside the share set
        shareSet[42] ^= 0xFF

        do {
            _ = try await self.state!.net.svr3.restore(
                password: "password",
                shareSet: shareSet,
                auth: self.state!.auth
            )
            XCTFail("Should have thrown")
        } catch SignalError.svrRestoreFailed(_, _) {
            // Success!
        } catch {
            XCTFail("Unexpected exception: '\(error)'")
        }
    }

    func testMaxRetries() async throws {
        let shareSet = try await state!.net.svr3.backup(
            self.storedSecret,
            password: "password",
            maxTries: 1,
            auth: self.state!.auth
        )
        // First restore should succeed, but use up all the available tries
        _ = try await self.state!.net.svr3.restore(
            password: "password",
            shareSet: shareSet,
            auth: self.state!.auth
        )

        do {
            _ = try await self.state!.net.svr3.restore(
                password: "password",
                shareSet: shareSet,
                auth: self.state!.auth
            )
            XCTFail("Should have thrown")
        } catch SignalError.svrDataMissing(_) {
            // Success!
        } catch {
            XCTFail("Unexpected exception: '\(error)'")
        }
    }

    func testMaxRetriesAfterFailure() async throws {
        let shareSet = try await state!.net.svr3.backup(
            self.storedSecret,
            password: "password",
            maxTries: 1,
            auth: self.state!.auth
        )
        // First restore fails **and** decrements the tries left counter
        do {
            _ = try await self.state!.net.svr3.restore(
                password: "invalid password",
                shareSet: shareSet,
                auth: self.state!.auth
            )
            XCTFail("Should have thrown")
        } catch SignalError.svrRestoreFailed(_, _) {
            // Success!
        } catch {
            XCTFail("Unexpected exception: '\(error)'")
        }

        do {
            _ = try await self.state!.net.svr3.restore(
                password: "password",
                shareSet: shareSet,
                auth: self.state!.auth
            )
            XCTFail("Should have thrown")
        } catch SignalError.svrDataMissing(_) {
            // Success!
        } catch {
            XCTFail("Unexpected exception: '\(error)'")
        }
    }

    func testInvalidMaxTries() async throws {
        do {
            _ = try await self.state!.net.svr3.backup(
                self.storedSecret,
                password: "password",
                maxTries: 0,
                auth: self.state!.auth
            )
            XCTFail("Should have thrown")
        } catch SignalError.invalidArgument(_) {
            // Success!
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testInvalidSecretSize() async throws {
        do {
            _ = try await self.state!.net.svr3.backup(
                randomBytes(42),
                password: "password",
                maxTries: 0,
                auth: self.state!.auth
            )
            XCTFail("Should have thrown")
        } catch SignalError.invalidArgument(_) {
            // Success!
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testInvalidEnclaveAuth() async throws {
        // calling it to make it an "integration test"
        _ = try self.getEnclaveSecret()
        let auth = Auth(username: randomBytes(16).hexString, password: randomBytes(32).hexString)

        do {
            _ = try await self.state!.net.svr3.backup(
                self.storedSecret,
                password: "password",
                maxTries: 10,
                auth: auth
            )
            XCTFail("Should have failed")
        } catch SignalError.webSocketError(let message) {
            XCTAssert(message.contains("401"))
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testRestoreAfterMigrate() async throws {
        // migrate is equivalent to backup, so this test merely validates that the "write" happens,
        // not that the value is removed from the old location.
        let tries = UInt32(10)

        let shareSet = try await state!.net.svr3.migrate(
            self.storedSecret,
            password: "password",
            maxTries: tries,
            auth: self.state!.auth
        )

        let restoredSecret = try await state!.net.svr3.restore(
            password: "password",
            shareSet: shareSet,
            auth: self.state!.auth
        )
        XCTAssertEqual(restoredSecret.value, self.storedSecret)
        XCTAssertEqual(restoredSecret.triesRemaining, tries - 1)
    }

    func testRestoreAfterRotate() async throws {
        let tries = UInt32(10)

        let shareSet = try await state!.net.svr3.backup(
            self.storedSecret,
            password: "password",
            maxTries: tries,
            auth: self.state!.auth
        )

        _ = try await self.state!.net.svr3.rotate(shareSet: shareSet, auth: self.state!.auth)

        let restoredSecret = try await state!.net.svr3.restore(
            password: "password",
            shareSet: shareSet,
            auth: self.state!.auth
        )
        XCTAssertEqual(restoredSecret.value, self.storedSecret)
        XCTAssertEqual(restoredSecret.triesRemaining, tries - 1)
    }
}

#endif
