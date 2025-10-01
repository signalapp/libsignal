//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

import Foundation
@testable import LibSignalClient
import SignalFfi
import Testing

let userAgent: String = "test"

final class NetTests {
    @Test
    func cdsiLookupResultConversion() async throws {
        let ACI_UUID = "9d0652a3-dcc3-4d11-975f-74d61598733f"
        let PNI_UUID = "796abedb-ca4e-4f18-8803-1fde5b921f9f"

        let aci = Aci(fromUUID: UUID(uuidString: ACI_UUID)!)
        let pni = Pni(fromUUID: UUID(uuidString: PNI_UUID)!)

        let asyncContext = TokioAsyncContext()

        let output: SignalFfiCdsiLookupResponse = try await asyncContext.invokeAsyncFunction { promise, asyncContext in
            signal_testing_cdsi_lookup_response_convert(promise, asyncContext.const())
        }
        #expect(output.debug_permits_used == 123)

        let entryList = LookupResponseEntryList(owned: output.entries)
        let expected = [
            SignalFfiCdsiLookupResponseEntry(
                e164: 18_005_551_011,
                aci,
                pni
            ),
            SignalFfiCdsiLookupResponseEntry(
                e164: 18_005_551_012,
                nil,
                pni
            ),
        ]

        #expect(expected == Array(entryList))
    }

    @Test
    func cdsiLookupErrorConversion() async throws {
        let failWithError = {
            try checkError(signal_testing_cdsi_lookup_error_convert($0))
            Issue.record("should have failed")
        }
        do {
            try failWithError("Protocol")
        } catch SignalError.networkProtocolError(let message) {
            #expect(
                message
                    == "Protocol error: protocol error after establishing a connection: failed to decode frame as protobuf"
            )
        }
        do {
            try failWithError("CdsiProtocol")
        } catch SignalError.networkProtocolError(let message) {
            #expect(message == "Protocol error: CDS protocol: no token found in response")
        }
        do {
            try failWithError("AttestationDataError")
        } catch SignalError.invalidAttestationData(let message) {
            #expect(message == "SGX operation failed: attestation data invalid: fake reason")
        }
        do {
            try failWithError("RetryAfter42Seconds")
        } catch SignalError.rateLimitedError(retryAfter: 42, let message) {
            #expect(message == "Rate limited; try again after 42s")
        }
        do {
            try failWithError("InvalidToken")
        } catch SignalError.cdsiInvalidToken(let message) {
            #expect(message == "CDSI request token was invalid")
        }
        do {
            try failWithError("InvalidArgument")
        } catch SignalError.invalidArgument(let message) {
            #expect(message == "invalid argument: request was invalid: fake reason")
        }
        do {
            try failWithError("TcpConnectFailed")
        } catch SignalError.ioError(let message) {
            #expect(message == "IO error: Failed to establish TCP connection to any of the IPs")
        }
        do {
            try failWithError("WebSocketIdleTooLong")
        } catch SignalError.webSocketError(let message) {
            #expect(message == "WebSocket error: channel was idle for too long")
        }
        do {
            try failWithError("AllConnectionAttemptsFailed")
        } catch SignalError.connectionFailed(let message) {
            #expect(message == "No connection attempts succeeded before timeout")
        }
        do {
            try failWithError("ServerCrashed")
        } catch SignalError.networkProtocolError(let message) {
            #expect(message == "Protocol error: server error: crashed")
        }
    }

    // Compile-only, no @Test
    func testCdsiLookupCompilation() async throws {
        let auth = Auth(username: "username", password: "password")
        let request = try CdsiLookupRequest(
            e164s: [],
            prevE164s: [],
            acisAndAccessKeys: [],
            token: nil
        )
        let net = Net(env: .staging, userAgent: userAgent, buildVariant: .production)

        let lookup = try await net.cdsiLookup(auth: auth, request: request)
        let response = try await lookup.complete()
        for entry in response.entries {
            _ = entry.aci
            _ = entry.pni
            _ = entry.e164
        }
    }

    @Test
    func networkChangeEvent() throws {
        // There's no feedback from this, we're just making sure it doesn't normally crash or throw.
        let net = Net(env: .staging, userAgent: userAgent, buildVariant: .production)
        try net.networkDidChange()
    }
}

#endif
