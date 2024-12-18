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
            signal_testing_cdsi_lookup_response_convert(promise, asyncContext.const())
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
            XCTAssertEqual(message, "Protocol error: protocol error after establishing a connection: failed to decode frame as protobuf")
        }
        do {
            try failWithError("CdsiProtocol")
        } catch SignalError.networkProtocolError(let message) {
            XCTAssertEqual(message, "Protocol error: CDS protocol: no token found in response")
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
            token: nil
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

#endif
