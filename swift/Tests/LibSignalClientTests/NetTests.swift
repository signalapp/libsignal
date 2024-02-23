//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

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

#endif
