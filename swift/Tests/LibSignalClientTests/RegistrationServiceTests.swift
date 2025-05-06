//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
@testable import LibSignalClient
import SignalFfi
import XCTest

class RegistrationServiceConversionTests: XCTestCase {
    private struct ErrorTest {
        public let operationName: String
        public let convertFn: (_: UnsafePointer<CChar>) -> OpaquePointer?
        public let cases: [(String, (Error) -> Bool)]
        public init(
            _ operationName: String,
            _ convertFn: @escaping (_: UnsafePointer<CChar>) -> OpaquePointer?,
            _ cases: [(String, (Error) -> Bool)]
        ) {
            self.operationName = operationName
            self.convertFn = convertFn
            self.cases = cases
        }
    }

    func testErrorConversion() {
        let retryLaterCase = ("RetryAfter42Seconds", { (e: Error) in if case SignalError.rateLimitedError(retryAfter: 42, message: "retry after 42s") = e { true } else { false }})
        let unknownCase = ("Unknown", { (e: Error) in if case RegistrationError.unknown("unknown error: some message") = e { true } else { false }})
        let timeoutCase = ("Timeout", { (e: Error) in if case SignalError.requestTimeoutError("the request timed out") = e { true } else { false }})

        let cases = [
            ErrorTest("CreateSession", signal_testing_registration_service_create_session_error_convert, [
                ("InvalidSessionId", { if case RegistrationError.invalidSessionId("invalid session ID value") = $0 { true } else { false }}),
                retryLaterCase,
                unknownCase,
                timeoutCase,
            ]),
        ]

        for item in cases {
            for (desc, checkErrorExpected) in item.cases {
                do {
                    print("Checking \(item.operationName) - \(desc)")
                    try desc.withCString { errorCase in
                        try checkError(item.convertFn(errorCase))
                    }
                    XCTFail("exception expected")
                } catch let e {
                    XCTAssert(checkErrorExpected(e), String(describing: e))
                }
            }
        }
    }
}
