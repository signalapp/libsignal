//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class UnauthProfilesServiceTests: UnauthChatServiceTestBase<any UnauthProfilesService> {
    override class var selector: SelectorCheck { .profiles }

    func testAccountExists() async throws {
        let ACI = Aci(fromUUID: UUID(uuidString: "9d0652a3-dcc3-4d11-975f-74d61598733f")!)
        let PNI = Pni(fromUUID: UUID(uuidString: "796abedb-ca4e-4f18-8803-1fde5b921f9f")!)
        let api = self.api
        struct TestCase {
            var serviceId: ServiceId
            var found: Bool
        }
        for testCase in [
            TestCase(serviceId: ACI, found: true),
            TestCase(serviceId: PNI, found: true),
            TestCase(serviceId: ACI, found: false),
            TestCase(serviceId: PNI, found: false),
        ] {
            async let responseFuture = api.accountExists(testCase.serviceId)
            let (request, id) = try await fakeRemote.getNextIncomingRequest()
            XCTAssertEqual(request.method, "HEAD")
            XCTAssertEqual(request.pathAndQuery, "/v1/accounts/account/\(testCase.serviceId.serviceIdString)")
            try fakeRemote.sendResponse(requestId: id, ChatResponse(status: testCase.found ? 200 : 404))
            let resp = try await responseFuture
            XCTAssertEqual(resp, testCase.found)
        }
    }
}

#endif
