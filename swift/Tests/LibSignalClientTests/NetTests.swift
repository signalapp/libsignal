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

final class NetTests: XCTestCase {
    func testCdsiLookupResultConversion() async throws {
        let ACI_UUID = "9d0652a3-dcc3-4d11-975f-74d61598733f"
        let PNI_UUID = "796abedb-ca4e-4f18-8803-1fde5b921f9f"

        let aci = Aci(fromUUID: UUID(uuidString: ACI_UUID)!)
        let pni = Pni(fromUUID: UUID(uuidString: PNI_UUID)!)

        let asyncContext = TokioAsyncContext()

        let output: SignalFfiCdsiLookupResponse = try await invokeAsyncFunction { promise, context in
            asyncContext.withNativeHandle { asyncContext in
                signal_testing_cdsi_lookup_response_convert(promise, context, asyncContext)
            }
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
        do {
            var ignoredOut = false
            try checkError(signal_testing_cdsi_lookup_error_convert(&ignoredOut))
            XCTFail("should have failed")
        } catch SignalError.networkProtocolError(_) {
            // good
        }
    }

    func testCdsiLookupCompilation() async throws {
        try throwSkipForCompileOnlyTest()

        let auth = Auth(username: "username", password: "password")
        let request = try CdsiLookupRequest(e164s: [], prevE164s: [], acisAndAccessKeys: [], token: nil, returnAcisWithoutUaks: false)
        let net = Net(env: .staging)

        let lookup = try await net.cdsiLookup(auth: auth, request: request, timeout: TimeInterval(0))
        let response = try await lookup.complete()
        for entry in response.entries {
            _ = entry.aci
            _ = entry.pni
            _ = entry.e164
        }
    }
}

final class Svr3Tests: TestCaseBase {
    private let username = randomBytes(16).hexString
    private let storedSecret = randomBytes(32)

    private let defaultTimeout = TimeInterval(10)

    func getEnclaveSecret() throws -> String {
        guard let enclaveSecret = ProcessInfo.processInfo.environment["ENCLAVE_SECRET"] else {
            throw XCTSkip("requires ENCLAVE_SECRET")
        }
        return enclaveSecret
    }

    func testBackupAndRestore() async throws {
        let auth = try Auth(username: self.username, enclaveSecret: self.getEnclaveSecret())
        let net = Net(env: .staging)

        let shareSet = try await net.svr3.backup(
            self.storedSecret,
            password: "password",
            maxTries: 10,
            auth: auth,
            timeout: self.defaultTimeout
        )

        let restoredSecret = try await net.svr3.restore(
            password: "password",
            shareSet: shareSet,
            auth: auth,
            timeout: self.defaultTimeout
        )
        XCTAssertEqual(restoredSecret, self.storedSecret)
    }

    func testInvalidPassword() async throws {
        let auth = try Auth(username: self.username, enclaveSecret: self.getEnclaveSecret())
        let net = Net(env: .staging)

        let shareSet = try await net.svr3.backup(
            self.storedSecret,
            password: "password",
            maxTries: 10,
            auth: auth,
            timeout: self.defaultTimeout
        )

        do {
            _ = try await net.svr3.restore(
                password: "invalid password",
                shareSet: shareSet,
                auth: auth,
                timeout: self.defaultTimeout
            )
            XCTFail("Should have thrown")
        } catch SignalError.svrRestoreFailed(_) {
            // Success!
        } catch {
            XCTFail("Unexpected exception: '\(error)'")
        }
    }

    func testCorruptedShareSet() async throws {
        let auth = try Auth(username: self.username, enclaveSecret: self.getEnclaveSecret())
        let net = Net(env: .staging)

        var shareSet = try await net.svr3.backup(
            self.storedSecret,
            password: "password",
            maxTries: 10,
            auth: auth,
            timeout: self.defaultTimeout
        )
        // Invert a byte somewhere inside the share set
        shareSet[42] ^= 0xFF

        do {
            _ = try await net.svr3.restore(
                password: "password",
                shareSet: shareSet,
                auth: auth,
                timeout: self.defaultTimeout
            )
            XCTFail("Should have thrown")
        } catch SignalError.svrRestoreFailed(_) {
            // Success!
        } catch {
            XCTFail("Unexpected exception: '\(error)'")
        }
    }

    func testMaxRetries() async throws {
        let auth = try Auth(username: self.username, enclaveSecret: self.getEnclaveSecret())
        let net = Net(env: .staging)

        let shareSet = try await net.svr3.backup(
            self.storedSecret,
            password: "password",
            maxTries: 1,
            auth: auth,
            timeout: self.defaultTimeout
        )
        // First restore should succeed, but use up all the available tries
        _ = try await net.svr3.restore(
            password: "password",
            shareSet: shareSet,
            auth: auth,
            timeout: self.defaultTimeout
        )

        do {
            _ = try await net.svr3.restore(
                password: "password",
                shareSet: shareSet,
                auth: auth,
                timeout: self.defaultTimeout
            )
            XCTFail("Should have thrown")
        } catch SignalError.svrDataMissing(_) {
            // Success!
        } catch {
            XCTFail("Unexpected exception: '\(error)'")
        }
    }

    func testMaxRetriesAfterFailure() async throws {
        let auth = try Auth(username: self.username, enclaveSecret: self.getEnclaveSecret())
        let net = Net(env: .staging)

        let shareSet = try await net.svr3.backup(
            self.storedSecret,
            password: "password",
            maxTries: 1,
            auth: auth,
            timeout: self.defaultTimeout
        )
        // First restore fails **and** decrements the tries left counter
        do {
            _ = try await net.svr3.restore(
                password: "invalid password",
                shareSet: shareSet,
                auth: auth,
                timeout: self.defaultTimeout
            )
            XCTFail("Should have thrown")
        } catch SignalError.svrRestoreFailed(_) {
            // Success!
        } catch {
            XCTFail("Unexpected exception: '\(error)'")
        }

        do {
            _ = try await net.svr3.restore(
                password: "password",
                shareSet: shareSet,
                auth: auth,
                timeout: self.defaultTimeout
            )
            XCTFail("Should have thrown")
        } catch SignalError.svrDataMissing(_) {
            // Success!
        } catch {
            XCTFail("Unexpected exception: '\(error)'")
        }
    }

    func testInvalidMaxTries() async throws {
        let auth = try Auth(username: self.username, enclaveSecret: self.getEnclaveSecret())
        let net = Net(env: .staging)

        do {
            _ = try await net.svr3.backup(
                self.storedSecret,
                password: "password",
                maxTries: 0,
                auth: auth,
                timeout: self.defaultTimeout
            )
            XCTFail("Should have thrown")
        } catch SignalError.invalidArgument(_) {
            // Success!
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testInvalidSecretSize() async throws {
        let auth = try Auth(username: self.username, enclaveSecret: self.getEnclaveSecret())
        let net = Net(env: .staging)

        do {
            _ = try await net.svr3.backup(
                randomBytes(42),
                password: "password",
                maxTries: 0,
                auth: auth,
                timeout: self.defaultTimeout
            )
            XCTFail("Should have thrown")
        } catch SignalError.invalidArgument(_) {
            // Success!
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }

    func testBackupTimeout() async throws {
        let auth = try Auth(username: self.username, enclaveSecret: self.getEnclaveSecret())
        let net = Net(env: .staging)

        do {
            _ = try await net.svr3.backup(
                self.storedSecret,
                password: "password",
                maxTries: 1,
                auth: auth,
                timeout: TimeInterval(0.01)
            )
            XCTFail("Should have thrown")
        } catch SignalError.timeoutError(let message) {
            // Make sure the logged message will provide enough details
            XCTAssertTrue(message.contains("Operation timed out"), "Unexpected message: '\(message)'")
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
}

#endif
