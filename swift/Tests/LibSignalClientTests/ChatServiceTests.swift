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

final class ChatServiceTests: XCTestCase {
    private static let expectedStatus: UInt16 = 200
    private static let expectedMessage = "OK"
    private static let expectedContent = "content".data(using: .utf8)
    private static let expectedHeaders = ["user-agent": "test", "forwarded": "1.1.1.1"]

    func testConvertResponse() throws {
        do {
            // Empty body
            var rawResponse = SignalFfiChatResponse()
            try checkError(signal_testing_chat_service_response_convert(&rawResponse, false))
            let response = try ChatService.Response(consuming: rawResponse)
            XCTAssertEqual(Self.expectedStatus, response.status)
            XCTAssertEqual(Self.expectedMessage, response.message)
            XCTAssertEqual(Self.expectedHeaders, response.headers)
            XCTAssert(response.body.isEmpty)
        }

        do {
            // Present body
            var rawResponse = SignalFfiChatResponse()
            try checkError(signal_testing_chat_service_response_convert(&rawResponse, true))
            let response = try ChatService.Response(consuming: rawResponse)
            XCTAssertEqual(Self.expectedStatus, response.status)
            XCTAssertEqual(Self.expectedMessage, response.message)
            XCTAssertEqual(Self.expectedHeaders, response.headers)
            XCTAssertEqual(Self.expectedContent, response.body)
        }
    }

    func testConvertDebugInfo() throws {
        var rawDebugInfo = SignalFfiChatServiceDebugInfo()
        try checkError(signal_testing_chat_service_debug_info_convert(&rawDebugInfo))
        let debugInfo = ChatService.DebugInfo(consuming: rawDebugInfo)
        XCTAssertTrue(debugInfo.connectionReused)
        XCTAssertEqual(2, debugInfo.reconnectCount)
        XCTAssertEqual(.ipv4, debugInfo.ipType)
        XCTAssertEqual(0.2, debugInfo.duration)
        XCTAssertEqual("connection_info", debugInfo.connectionInfo)
    }

    func testConvertResponseAndDebugInfo() throws {
        var rawResponseAndDebugInfo = SignalFfiResponseAndDebugInfo()
        try checkError(signal_testing_chat_service_response_and_debug_info_convert(&rawResponseAndDebugInfo))

        let response = try ChatService.Response(consuming: rawResponseAndDebugInfo.response)
        XCTAssertEqual(Self.expectedStatus, response.status)
        XCTAssertEqual(Self.expectedMessage, response.message)
        XCTAssertEqual(Self.expectedHeaders, response.headers)
        XCTAssertEqual(Self.expectedContent, response.body)

        let debugInfo = ChatService.DebugInfo(consuming: rawResponseAndDebugInfo.debug_info)
        XCTAssertTrue(debugInfo.connectionReused)
        XCTAssertEqual(2, debugInfo.reconnectCount)
        XCTAssertEqual(.ipv4, debugInfo.ipType)
        XCTAssertEqual(0.2, debugInfo.duration)
        XCTAssertEqual("connection_info", debugInfo.connectionInfo)
    }

    func testConvertError() throws {
        do {
            try checkError(signal_testing_chat_service_error_convert())
        } catch SignalError.connectionTimeoutError(_) {
            // Okay
        }
        do {
            try checkError(signal_testing_chat_service_inactive_error_convert())
        } catch SignalError.chatServiceInactive(_) {
            // Okay
        }
    }

    func testConstructRequest() throws {
        let expectedMethod = "GET"
        let expectedPathAndQuery = "/test"

        let request = ChatService.Request(method: expectedMethod, pathAndQuery: expectedPathAndQuery, headers: Self.expectedHeaders, body: Self.expectedContent, timeout: 5)
        let internalRequest = try ChatService.InternalRequest(request)
        try internalRequest.withNativeHandle { internalRequest in
            XCTAssertEqual(expectedMethod, try invokeFnReturningString {
                signal_testing_chat_request_get_method($0, internalRequest)
            })
            XCTAssertEqual(expectedPathAndQuery, try invokeFnReturningString {
                signal_testing_chat_request_get_path($0, internalRequest)
            })
            XCTAssertEqual(Self.expectedContent, try invokeFnReturningData {
                signal_testing_chat_request_get_body($0, internalRequest)
            })
            for (k, v) in Self.expectedHeaders {
                XCTAssertEqual(v, try invokeFnReturningString {
                    signal_testing_chat_request_get_header_value($0, internalRequest, k)
                })
            }
        }
    }
}

#endif
