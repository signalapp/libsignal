//
// Copyright 2024 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
@testable import LibSignalClient
import SignalFfi
import XCTest

extension ConnectionManager {
    func assertIsUsingProxyIs(_ value: Int32) {
// The testing native function used to implement this isn't available on device
// builds to save on code size. If it's present use it, otherwise this is a no-op.
#if !os(iOS) || targetEnvironment(simulator)
        let isUsingProxy =
            withNativeHandle { handle in
                failOnError {
                    try invokeFnReturningInteger {
                        signal_testing_connection_manager_is_using_proxy($0, handle.const())
                    }
                }
            }
        XCTAssertEqual(isUsingProxy, value)
#endif
    }
}

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
            try checkError(signal_testing_chat_response_convert(&rawResponse, false))
            let response = try ChatConnection.Response(consuming: rawResponse)
            XCTAssertEqual(Self.expectedStatus, response.status)
            XCTAssertEqual(Self.expectedMessage, response.message)
            XCTAssertEqual(Self.expectedHeaders, response.headers)
            XCTAssert(response.body.isEmpty)
        }

        do {
            // Present body
            var rawResponse = SignalFfiChatResponse()
            try checkError(signal_testing_chat_response_convert(&rawResponse, true))
            let response = try ChatConnection.Response(consuming: rawResponse)
            XCTAssertEqual(Self.expectedStatus, response.status)
            XCTAssertEqual(Self.expectedMessage, response.message)
            XCTAssertEqual(Self.expectedHeaders, response.headers)
            XCTAssertEqual(Self.expectedContent, response.body)
        }
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
            try failWithError("Disconnected")
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
            try failWithError("RequestSendTimedOut")
        } catch SignalError.requestTimeoutError(_) {}
        do {
            try failWithError("TimeoutEstablishingConnection")
        } catch SignalError.connectionTimeoutError(_) {}

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

        let request = ChatConnection.Request(method: expectedMethod, pathAndQuery: expectedPathAndQuery, headers: Self.expectedHeaders, body: Self.expectedContent, timeout: 5)
        let internalRequest = try ChatConnection.Request.InternalRequest(request)
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

#endif

    func testInvalidProxyRejected() {
        let net = Net(env: .production, userAgent: Self.userAgent)

        func check(callback: () throws -> Void) {
            net.connectionManager.assertIsUsingProxyIs(0)
            do {
                try callback()
                XCTFail("should not allow setting invalid proxy")
            } catch SignalError.ioError {
                // Okay
                net.connectionManager.assertIsUsingProxyIs(-1)
            } catch {
                XCTFail("unexpected error: \(error)")
            }
            net.clearProxy()
        }

        check {
            try net.setProxy(host: "signalfoundation.org", port: 0)
        }
        check {
            try net.setProxy(scheme: "socks+shoes", host: "signalfoundation.org")
        }
        check {
            net.setInvalidProxy()
            throw SignalError.ioError("to match all the other test cases")
        }
    }
}

final class ChatConnectionTests: TestCaseBase {
    private static let userAgent = "test"

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)
    func testListenerCallbacks() async throws {
        class Listener: ChatConnectionListener {
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

            func chatConnection(_ chat: AuthenticatedChatConnection, didReceiveIncomingMessage envelope: Data, serverDeliveryTimestamp: UInt64, sendAck: () throws -> Void) {
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

            func chatConnectionDidReceiveQueueEmpty(_: AuthenticatedChatConnection) {
                self.queueEmpty.fulfill()
            }

            func connectionWasInterrupted(_: AuthenticatedChatConnection, error: Error?) {
                XCTAssertNotNil(error)
                self.connectionInterrupted.fulfill()
            }
        }

        let tokioAsyncContext = TokioAsyncContext()
        let listener = Listener(
            queueEmpty: expectation(description: "queue empty"),
            firstMessageReceived: expectation(description: "first message received"),
            secondMessageReceived: expectation(description: "second message received"),
            connectionInterrupted: expectation(description: "connection interrupted")
        )
        let (chat, fakeRemote) = AuthenticatedChatConnection.fakeConnect(tokioAsyncContext: tokioAsyncContext, listener: listener)
        // Make sure the chat object doesn't go away too soon.
        defer { withExtendedLifetime(chat) {} }

        // The following payloads were generated via protoscope.
        // % protoscope -s | base64
        // The fields are described by chat_websocket.proto in the libsignal-net crate.

        // 1: {"PUT"}
        // 2: {"/api/v1/message"}
        // 3: {1000i64}
        // 5: {"x-signal-timestamp:1000"}
        // 4: 1
        fakeRemote.injectServerRequest(base64: "CgNQVVQSDy9hcGkvdjEvbWVzc2FnZRoI6AMAAAAAAAAqF3gtc2lnbmFsLXRpbWVzdGFtcDoxMDAwIAE=")
        // 1: {"PUT"}
        // 2: {"/api/v1/message"}
        // 3: {2000i64}
        // 5: {"x-signal-timestamp:2000"}
        // 4: 2
        fakeRemote.injectServerRequest(base64: "CgNQVVQSDy9hcGkvdjEvbWVzc2FnZRoI0AcAAAAAAAAqF3gtc2lnbmFsLXRpbWVzdGFtcDoyMDAwIAI=")

        // Sending an invalid message should not affect the listener at all, nor should it stop future requests.
        // 1: {"PUT"}
        // 2: {"/invalid"}
        // 4: 10
        fakeRemote.injectServerRequest(base64: "CgNQVVQSCC9pbnZhbGlkIAo=")

        // 1: {"PUT"}
        // 2: {"/api/v1/queue/empty"}
        // 4: 99
        fakeRemote.injectServerRequest(base64: "CgNQVVQSEy9hcGkvdjEvcXVldWUvZW1wdHkgYw==")

        fakeRemote.injectConnectionInterrupted()

        await self.fulfillment(of: listener.expectations, timeout: 2, enforceOrder: true)
    }

    func testSending() async throws {
        class NoOpListener: ChatConnectionListener {
            func chatConnection(_ chat: AuthenticatedChatConnection, didReceiveIncomingMessage envelope: Data, serverDeliveryTimestamp: UInt64, sendAck: () throws -> Void) {}

            func connectionWasInterrupted(_: AuthenticatedChatConnection, error: Error?) {}
        }
        let tokioAsyncContext = TokioAsyncContext()
        let (chat, fakeRemote) = AuthenticatedChatConnection.fakeConnect(tokioAsyncContext: tokioAsyncContext, listener: NoOpListener())
        defer { withExtendedLifetime(chat) {} }

        let request = ChatRequest(method: "PUT", pathAndQuery: "/some/path", headers: ["purpose": "test request"], body: Data([1, 1, 2, 3]), timeout: TimeInterval(5))
        async let responseFuture = chat.send(request)

        let (requestFromServer, id) = try await fakeRemote.getNextIncomingRequest()
        try requestFromServer.withNativeHandle { requestFromServer in

            XCTAssertEqual(request.method, try invokeFnReturningString {
                signal_testing_chat_request_get_method($0, requestFromServer.const())
            })
            XCTAssertEqual(request.pathAndQuery, try invokeFnReturningString {
                signal_testing_chat_request_get_path($0, requestFromServer.const())
            })
            XCTAssertEqual(request.body, try invokeFnReturningData {
                signal_testing_chat_request_get_body($0, requestFromServer.const())
            })
            for (k, v) in request.headers {
                XCTAssertEqual(v, try invokeFnReturningString {
                    signal_testing_chat_request_get_header_value($0, requestFromServer.const(), k)
                })
            }
        }
        XCTAssertEqual(id, 0)

        // 1: 0
        // 2: 201
        // 3: {"Created"}
        // 5: {"purpose: test response"}
        // 4: {5}
        fakeRemote.injectServerResponse(base64: "CAAQyQEaB0NyZWF0ZWQqFnB1cnBvc2U6IHRlc3QgcmVzcG9uc2UiAQU=")

        let responseFromServer = try await responseFuture
        XCTAssertEqual(responseFromServer.status, 201)
        XCTAssertEqual(responseFromServer.message, "Created")
        XCTAssertEqual(responseFromServer.headers, ["purpose": "test response"])
        XCTAssertEqual(responseFromServer.body, Data([5]))
    }
#endif

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
        // If we destroy the ChatConnection, we should also clean up the listener.
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
        net.connectionManager.assertIsUsingProxyIs(1)

        let chat = try await net.connectUnauthenticatedChat()
        let listener = ExpectDisconnectListener(expectation(description: "disconnect"))
        chat.start(listener: listener)

        // Just make sure we can connect.
        try await chat.disconnect()

        await self.fulfillment(of: [listener.expectation], timeout: 2)
    }

    func testConnectUnauthThroughProxyByParts() async throws {
        guard let PROXY_SERVER = ProcessInfo.processInfo.environment["LIBSIGNAL_TESTING_PROXY_SERVER"] else {
            throw XCTSkip()
        }

        // The default TLS proxy config doesn't support staging, so we connect to production.
        let net = Net(env: .production, userAgent: Self.userAgent)
        let host: Substring
        let port: UInt16?
        if let colonIndex = PROXY_SERVER.firstIndex(of: ":") {
            host = PROXY_SERVER[..<colonIndex]
            port = UInt16(PROXY_SERVER[colonIndex...].dropFirst())!
        } else {
            host = PROXY_SERVER[...]
            port = nil
        }

        let user: Substring?
        let justTheHost: Substring
        if let atIndex = host.firstIndex(of: "@") {
            user = host[..<atIndex]
            justTheHost = host[atIndex...].dropFirst()
        } else {
            user = nil
            justTheHost = host
        }

        try net.setProxy(
            scheme: Net.signalTlsProxyScheme,
            host: String(justTheHost),
            port: port,
            username: user.map(String.init)
        )
        net.connectionManager.assertIsUsingProxyIs(1)

        // Just make sure we can connect.
        let _: UnauthenticatedChatConnection = try await net.connectUnauthenticatedChat()
    }

    func testDisconnectWithoutListener() async throws {
        // Use the presence of the environment setting to know whether we should make network requests in our tests.
        guard ProcessInfo.processInfo.environment["LIBSIGNAL_TESTING_RUN_NONHERMETIC_TESTS"] != nil else {
            throw XCTSkip()
        }

        let net = Net(env: .staging, userAgent: Self.userAgent)
        let chat = try await net.connectUnauthenticatedChat()
        // Intentionally don't call .start and set a listener; sometimes the client app does not do this before
        // calling .disconnect()
        try await chat.disconnect()
    }
}
