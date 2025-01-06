//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
@testable import LibSignalClient
import SignalFfi
import XCTest

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

extension AuthenticatedChatService {
    func injectServerRequest(base64: String) {
        self.injectServerRequest(Data(base64Encoded: base64)!)
    }

    func injectServerRequest(_ requestBytes: Data) {
        withNativeHandle { handle in
            requestBytes.withUnsafeBorrowedBuffer { requestBytes in
                failOnError(signal_testing_chat_service_inject_raw_server_request(handle.const(), requestBytes))
            }
        }
    }

    func injectConnectionInterrupted() {
        withNativeHandle { handle in
            failOnError(signal_testing_chat_service_inject_connection_interrupted(handle.const()))
        }
    }
}

#endif

final class ChatServiceTests: TestCaseBase {
    private static let userAgent = "test"

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

    private static let expectedStatus: UInt16 = 200
    private static let expectedMessage = "OK"
    private static let expectedContent = Data("content".utf8)
    private static let expectedHeaders = ["content-type": "application/octet-stream", "forwarded": "1.1.1.1"]

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
        XCTAssertEqual(.ipv4, debugInfo.ipType)
        XCTAssertEqual(0.2, debugInfo.duration)
        XCTAssertEqual("connection_info", debugInfo.connectionInfo)
    }

    func testConvertError() throws {
        let failWithError = {
            try checkError(signal_testing_chat_service_error_convert($0))
            XCTFail("should have failed")
        }
        do {
            try failWithError("AppExpired")
        } catch SignalError.appExpired(_) {}
        do {
            try failWithError("DeviceDeregistered")
        } catch SignalError.deviceDeregistered(_) {}
        do {
            try failWithError("ServiceInactive")
        } catch SignalError.chatServiceInactive(_) {}

        do {
            try failWithError("WebSocket")
        } catch SignalError.webSocketError(_) {}
        do {
            try failWithError("UnexpectedFrameReceived")
        } catch SignalError.networkProtocolError(_) {}
        do {
            try failWithError("ServerRequestMissingId")
        } catch SignalError.networkProtocolError(_) {}
        do {
            try failWithError("IncomingDataInvalid")
        } catch SignalError.networkProtocolError(_) {}
        do {
            try failWithError("Timeout")
        } catch SignalError.connectionTimeoutError(_) {}
        do {
            try failWithError("TimeoutEstablishingConnection")
        } catch SignalError.connectionTimeoutError(_) {}

        do {
            try failWithError("FailedToPassMessageToIncomingChannel")
        } catch SignalError.internalError(_) {}
        do {
            try failWithError("RequestHasInvalidHeader")
        } catch SignalError.internalError(_) {}
        do {
            try failWithError("RetryAfter42Seconds")
        } catch SignalError.rateLimitedError(retryAfter: 42, let message) {
            XCTAssertEqual(message, "Rate limited; try again after 42s")
        }
    }

    func testConstructRequest() throws {
        let expectedMethod = "GET"
        let expectedPathAndQuery = "/test"

        let request = ChatService.Request(method: expectedMethod, pathAndQuery: expectedPathAndQuery, headers: Self.expectedHeaders, body: Self.expectedContent, timeout: 5)
        let internalRequest = try ChatService.Request.InternalRequest(request)
        try internalRequest.withNativeHandle { internalRequest in
            XCTAssertEqual(expectedMethod, try invokeFnReturningString {
                signal_testing_chat_request_get_method($0, internalRequest.const())
            })
            XCTAssertEqual(expectedPathAndQuery, try invokeFnReturningString {
                signal_testing_chat_request_get_path($0, internalRequest.const())
            })
            XCTAssertEqual(Self.expectedContent, try invokeFnReturningData {
                signal_testing_chat_request_get_body($0, internalRequest.const())
            })
            for (k, v) in Self.expectedHeaders {
                XCTAssertEqual(v, try invokeFnReturningString {
                    signal_testing_chat_request_get_header_value($0, internalRequest.const(), k)
                })
            }
        }
    }

    func testListenerCallbacks() async throws {
        class Listener: ChatServiceListener {
            let queueEmpty: XCTestExpectation
            let firstMessageReceived: XCTestExpectation
            let secondMessageReceived: XCTestExpectation
            let connectionInterrupted: XCTestExpectation

            var expectations: [XCTestExpectation] {
                [self.firstMessageReceived, self.secondMessageReceived, self.queueEmpty, self.connectionInterrupted]
            }

            init(queueEmpty: XCTestExpectation, firstMessageReceived: XCTestExpectation, secondMessageReceived: XCTestExpectation, connectionInterrupted: XCTestExpectation) {
                self.queueEmpty = queueEmpty
                self.firstMessageReceived = firstMessageReceived
                self.secondMessageReceived = secondMessageReceived
                self.connectionInterrupted = connectionInterrupted
            }

            func chatService(_ chat: AuthenticatedChatService, didReceiveIncomingMessage envelope: Data, serverDeliveryTimestamp: UInt64, sendAck: () async throws -> Void) {
                // This assumes a little-endian platform.
                XCTAssertEqual(envelope, withUnsafeBytes(of: serverDeliveryTimestamp) { Data($0) })
                switch serverDeliveryTimestamp {
                case 1000:
                    self.firstMessageReceived.fulfill()
                case 2000:
                    self.secondMessageReceived.fulfill()
                default:
                    XCTFail("unexpected message")
                }
            }

            func chatServiceDidReceiveQueueEmpty(_: AuthenticatedChatService) {
                self.queueEmpty.fulfill()
            }

            func connectionWasInterrupted(_: AuthenticatedChatService, error: Error?) {
                XCTAssertNotNil(error)
                self.connectionInterrupted.fulfill()
            }
        }

        let net = Net(env: .staging, userAgent: Self.userAgent)
        let chat = net.createAuthenticatedChatService(username: "", password: "", receiveStories: false)
        let listener = Listener(
            queueEmpty: expectation(description: "queue empty"),
            firstMessageReceived: expectation(description: "first message received"),
            secondMessageReceived: expectation(description: "second message received"),
            connectionInterrupted: expectation(description: "connection interrupted")
        )
        chat.setListener(listener)

        // The following payloads were generated via protoscope.
        // % protoscope -s | base64
        // The fields are described by chat_websocket.proto in the libsignal-net crate.

        // 1: {"PUT"}
        // 2: {"/api/v1/message"}
        // 3: {1000i64}
        // 5: {"x-signal-timestamp:1000"}
        // 4: 1
        chat.injectServerRequest(base64: "CgNQVVQSDy9hcGkvdjEvbWVzc2FnZRoI6AMAAAAAAAAqF3gtc2lnbmFsLXRpbWVzdGFtcDoxMDAwIAE=")
        // 1: {"PUT"}
        // 2: {"/api/v1/message"}
        // 3: {2000i64}
        // 5: {"x-signal-timestamp:2000"}
        // 4: 2
        chat.injectServerRequest(base64: "CgNQVVQSDy9hcGkvdjEvbWVzc2FnZRoI0AcAAAAAAAAqF3gtc2lnbmFsLXRpbWVzdGFtcDoyMDAwIAI=")

        // Sending an invalid message should not affect the listener at all, nor should it stop future requests.
        // 1: {"PUT"}
        // 2: {"/invalid"}
        // 4: 10
        chat.injectServerRequest(base64: "CgNQVVQSCC9pbnZhbGlkIAo=")

        // 1: {"PUT"}
        // 2: {"/api/v1/queue/empty"}
        // 4: 99
        chat.injectServerRequest(base64: "CgNQVVQSEy9hcGkvdjEvcXVldWUvZW1wdHkgYw==")

        chat.injectConnectionInterrupted()

        await self.fulfillment(of: listener.expectations, timeout: 2, enforceOrder: true)
    }

#endif

    func testListenerCleanup() async throws {
        class Listener: ChatServiceListener {
            let expectation: XCTestExpectation
            init(expectation: XCTestExpectation) {
                self.expectation = expectation
            }

            deinit {
                expectation.fulfill()
            }

            func chatServiceDidReceiveQueueEmpty(_: AuthenticatedChatService) {}
            func chatService(_ chat: AuthenticatedChatService, didReceiveIncomingMessage envelope: Data, serverDeliveryTimestamp: UInt64, sendAck: () async throws -> Void) {}
            func connectionWasInterrupted(_ service: AuthenticatedChatService, error: Error?) {}
        }

        let net = Net(env: .staging, userAgent: Self.userAgent)
        var expectations: [XCTestExpectation] = []

        do {
            let chat = net.createAuthenticatedChatService(username: "", password: "", receiveStories: false)

            do {
                let expectation = expectation(description: "first listener destroyed")
                expectations.append(expectation)
                let listener = Listener(expectation: expectation)
                chat.setListener(listener)
            }
            do {
                let expectation = expectation(description: "second listener destroyed")
                expectations.append(expectation)
                let listener = Listener(expectation: expectation)
                chat.setListener(listener)
            }
            // Clearing the listener has a separate implementation, so let's make sure both get destroyed.
            chat.setListener(nil)
            await fulfillment(of: expectations, timeout: 2, enforceOrder: true)
            expectations.removeAll()

            do {
                let expectation = expectation(description: "third listener destroyed")
                expectations.append(expectation)
                let listener = Listener(expectation: expectation)
                chat.setListener(listener)
            }
        }
        // If we destroy the ChatService, we should also clean up the listener.
        await fulfillment(of: expectations, timeout: 2, enforceOrder: true)
    }

    final class ExpectDisconnectListener: ConnectionEventsListener {
        let expectation: XCTestExpectation

        init(_ expectation: XCTestExpectation) {
            self.expectation = expectation
        }

        func connectionWasInterrupted(_: UnauthenticatedChatService, error: Error?) {
            XCTAssertNil(error)
            self.expectation.fulfill()
        }
    }

    func testConnectUnauth() async throws {
        // Use the presence of the environment setting to know whether we should make network requests in our tests.
        guard ProcessInfo.processInfo.environment["LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS"] != nil else {
            throw XCTSkip()
        }

        let net = Net(env: .staging, userAgent: Self.userAgent)
        let chat = net.createUnauthenticatedChatService()
        let listener = ExpectDisconnectListener(expectation(description: "disconnect"))
        chat.setListener(listener)

        // Just make sure we can connect.
        try await chat.connect()
        try await chat.disconnect()

        await self.fulfillment(of: [listener.expectation], timeout: 2)
    }

    func testConnectUnauthThroughProxy() async throws {
        guard let PROXY_SERVER = ProcessInfo.processInfo.environment["LIBSIGNAL_TESTING_PROXY_SERVER"] else {
            throw XCTSkip()
        }

        // The default TLS proxy config doesn't support staging, so we connect to production.
        let net = Net(env: .production, userAgent: Self.userAgent)
        let host: Substring
        let port: UInt16
        if let colonIndex = PROXY_SERVER.firstIndex(of: ":") {
            host = PROXY_SERVER[..<colonIndex]
            port = UInt16(PROXY_SERVER[colonIndex...].dropFirst())!
        } else {
            host = PROXY_SERVER[...]
            port = 443
        }
        try net.setProxy(host: String(host), port: port)

        let chat = net.createUnauthenticatedChatService()
        let listener = ExpectDisconnectListener(expectation(description: "disconnect"))
        chat.setListener(listener)

        // Just make sure we can connect.
        try await chat.connect()
        try await chat.disconnect()

        await self.fulfillment(of: [listener.expectation], timeout: 2)
    }

    func testInvalidProxyRejected() async throws {
        // The default TLS proxy config doesn't support staging, so we connect to production.
        let net = Net(env: .production, userAgent: Self.userAgent)
        do {
            try net.setProxy(host: "signalfoundation.org", port: 0)
            XCTFail("should not allow setting invalid proxy")
        } catch SignalError.ioError {
            // Okay
        }
    }
}

final class ChatConnectionTests: TestCaseBase {
    private static let userAgent = "test"

    func testListenerCleanup() async throws {
        // Use the presence of the environment setting to know whether we should make network requests in our tests.
        guard ProcessInfo.processInfo.environment["LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS"] != nil else {
            throw XCTSkip()
        }
        class Listener: ConnectionEventsListener {
            let expectation: XCTestExpectation
            init(expectation: XCTestExpectation) {
                self.expectation = expectation
            }

            deinit {
                expectation.fulfill()
            }

            func connectionWasInterrupted(_ service: UnauthenticatedChatConnection, error: Error?) {}
        }

        let net = Net(env: .staging, userAgent: Self.userAgent)
        var expectations: [XCTestExpectation] = []

        do {
            let chat = try await net.connectUnauthenticatedChat()
            let expectation = expectation(description: "second listener destroyed")
            expectations.append(expectation)
            let listener = Listener(expectation: expectation)
            chat.start(listener: listener)
        }
        // If we destroy the ChatService, we should also clean up the listener.
        await fulfillment(of: expectations, timeout: 2, enforceOrder: true)
    }

    final class ExpectDisconnectListener: ConnectionEventsListener {
        let expectation: XCTestExpectation

        init(_ expectation: XCTestExpectation) {
            self.expectation = expectation
        }

        func connectionWasInterrupted(_: UnauthenticatedChatConnection, error: Error?) {
            XCTAssertNil(error)
            self.expectation.fulfill()
        }
    }

    func testConnectUnauth() async throws {
        // Use the presence of the environment setting to know whether we should make network requests in our tests.
        guard ProcessInfo.processInfo.environment["LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS"] != nil else {
            throw XCTSkip()
        }

        let net = Net(env: .staging, userAgent: Self.userAgent)
        let chat = try await net.connectUnauthenticatedChat()
        _ = chat.info()
        let listener = ExpectDisconnectListener(expectation(description: "disconnect"))
        chat.start(listener: listener)

        // Just make sure we can connect.
        try await chat.disconnect()

        await self.fulfillment(of: [listener.expectation], timeout: 2)
    }

    func testConnectUnauthThroughProxy() async throws {
        guard let PROXY_SERVER = ProcessInfo.processInfo.environment["LIBSIGNAL_TESTING_PROXY_SERVER"] else {
            throw XCTSkip()
        }

        // The default TLS proxy config doesn't support staging, so we connect to production.
        let net = Net(env: .production, userAgent: Self.userAgent)
        let host: Substring
        let port: UInt16
        if let colonIndex = PROXY_SERVER.firstIndex(of: ":") {
            host = PROXY_SERVER[..<colonIndex]
            port = UInt16(PROXY_SERVER[colonIndex...].dropFirst())!
        } else {
            host = PROXY_SERVER[...]
            port = 443
        }
        try net.setProxy(host: String(host), port: port)

        let chat = try await net.connectUnauthenticatedChat()
        let listener = ExpectDisconnectListener(expectation(description: "disconnect"))
        chat.start(listener: listener)

        // Just make sure we can connect.
        try await chat.disconnect()

        await self.fulfillment(of: [listener.expectation], timeout: 2)
    }
}
