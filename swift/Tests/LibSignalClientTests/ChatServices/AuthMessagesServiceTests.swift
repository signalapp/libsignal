//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

private let recipientUuid = UUID(uuidString: "4FCFE887-A600-40CD-9AB7-FD2A695E9981")!

class AuthMessagesServiceTests: AuthChatServiceTestBase<any AuthMessagesService> {
    override class var selector: SelectorCheck { .attachments }

    func testGetUploadForm() async throws {
        let api = self.api
        async let responseFuture = api.getUploadForm(uploadSize: 42)
        let (request, id) = try await fakeRemote.getNextIncomingRequest()
        XCTAssertEqual(request.method, "GET")
        XCTAssertEqual(request.pathAndQuery, "/v4/attachments/form/upload?uploadLength=42")
        XCTAssertEqual(request.headers.count, 0)
        XCTAssertEqual(request.body.count, 0)
        try fakeRemote.sendResponse(
            requestId: id,
            ChatResponse(
                status: 200,
                message: "OK",
                headers: ["content-type": "application/json"],
                body: Data(
                    """
                    {
                      "cdn":123,
                      "key":"abcde",
                      "headers":{"one":"val1","two":"val2"},
                      "signedUploadLocation":"http://example.org/upload"
                    }
                    """.utf8
                )
            )
        )
        let uploadForm = try await responseFuture
        XCTAssertEqual(
            uploadForm,
            UploadForm(
                cdn: 123,
                key: "abcde",
                headers: ["one": "val1", "two": "val2"],
                signedUploadUrl: URL(string: "http://example.org/upload")!,
            )
        )
    }
    func testGetUploadFormTooLarge() async throws {
        let api = self.api
        async let responseFuture = api.getUploadForm(uploadSize: 42)
        let (request, id) = try await fakeRemote.getNextIncomingRequest()
        XCTAssertEqual(request.method, "GET")
        XCTAssertEqual(request.pathAndQuery, "/v4/attachments/form/upload?uploadLength=42")
        XCTAssertEqual(request.headers.count, 0)
        XCTAssertEqual(request.body.count, 0)
        try fakeRemote.sendResponse(
            requestId: id,
            ChatResponse(
                status: 413,
                message: "Content Too Large",
            )
        )
        do {
            _ = try await responseFuture
            XCTFail("Failed to throw")
        } catch SignalError.uploadTooLarge(_) {}
    }

    private func sendTestMessage(
        syncMessage: Bool,
        response: ChatResponse
    ) async throws {
        let api = self.api

        // swift-format-ignore: GroupNumericLiterals
        let timestamp: UInt64 = 1700000000000
        let contents = [
            SingleOutboundUnsealedMessage(
                deviceId: DeviceId(validating: 1)!,
                registrationId: 11,
                contents: CiphertextMessage(try! PlaintextContent(bytes: [0xC0, 1, 2, 3, 0x80]))
            ),
            SingleOutboundUnsealedMessage(
                deviceId: DeviceId(validating: 2)!,
                registrationId: 22,
                contents: CiphertextMessage(try! PlaintextContent(bytes: [0xC0, 4, 5, 6, 0x80]))
            ),
        ]
        async let result: Void =
            syncMessage
            ? api.sendSyncMessage(timestamp: timestamp, contents: contents, urgent: true)
            : api.sendMessage(
                to: Aci(fromUUID: recipientUuid),
                timestamp: timestamp,
                contents: contents,
                onlineOnly: false,
                urgent: true
            )

        // Get the incoming request from the fake remote
        let (request, id) = try await fakeRemote.getNextIncomingRequest()

        XCTAssertEqual(request.method, "PUT")
        let expectedDestination = syncMessage ? FakeChatRemote.FAKE_AUTH_CONNECT_SELF_UUID : recipientUuid
        XCTAssertEqual(
            request.pathAndQuery,
            "/v1/messages/\(expectedDestination.uuidString.lowercased())"
        )
        XCTAssertEqual(request.headers, ["content-type": "application/json"])
        guard let requestBody = try JSONSerialization.jsonObject(with: request.body) as? NSDictionary else {
            fatalError("request was not a JSON dictionary")
        }
        // swift-format-ignore: GroupNumericLiterals
        XCTAssertEqual(
            requestBody,
            [
                "messages": [
                    [
                        "type": 8,
                        "destinationDeviceId": 1,
                        "destinationRegistrationId": 11,
                        "content": "wAECA4A=",
                    ],
                    [
                        "type": 8,
                        "destinationDeviceId": 2,
                        "destinationRegistrationId": 22,
                        "content": "wAQFBoA=",
                    ],
                ],
                "online": false,
                "urgent": true,
                "timestamp": 1700000000000,
            ] as NSDictionary
        )

        try fakeRemote.sendResponse(
            requestId: id,
            response
        )
        try await result
    }

    func testSendMessageSuccess() async throws {
        for syncMessage in [false, true] {
            try await self.sendTestMessage(
                syncMessage: syncMessage,
                response: ChatResponse(
                    status: 200,
                    headers: ["content-type": "application/json"],
                    body: Data("{}".utf8)
                )
            )
        }
    }

    func testSendMessageNotFound() async throws {
        do {
            _ = try await self.sendTestMessage(
                syncMessage: false,
                response: ChatResponse(status: 404)
            )
            XCTFail("should have thrown")
        } catch SignalError.serviceIdNotFound(_:) {
        }
    }

    func testSendMessageMismatchedDevices() async throws {
        do {
            _ = try await self.sendTestMessage(
                syncMessage: false,
                response: ChatResponse(
                    status: 409,
                    headers: ["content-type": "application/json"],
                    body: Data(
                        """
                        {
                            "missingDevices": [4, 5],
                            "extraDevices": [40, 50]
                        }
                        """.utf8
                    )
                )
            )
            XCTFail("should have thrown")
        } catch SignalError.mismatchedDevices(let entries, message: _) {
            XCTAssertEqual(entries.count, 1)
            let entry = entries[0]
            XCTAssertEqual(entry.account, Aci(fromUUID: recipientUuid))
            XCTAssertEqual(entry.missingDevices, [4, 5])
            XCTAssertEqual(entry.extraDevices, [40, 50])
            XCTAssertEqual(entry.staleDevices, [])
        }
    }

    func testSendMessageStaleDevices() async throws {
        do {
            _ = try await self.sendTestMessage(
                syncMessage: false,
                response: ChatResponse(
                    status: 410,
                    headers: ["content-type": "application/json"],
                    body: Data(
                        """
                        {
                            "staleDevices": [4, 5]
                        }
                        """.utf8
                    )
                )
            )
            XCTFail("should have thrown")
        } catch SignalError.mismatchedDevices(let entries, message: _) {
            XCTAssertEqual(entries.count, 1)
            let entry = entries[0]
            XCTAssertEqual(entry.account, Aci(fromUUID: recipientUuid))
            XCTAssertEqual(entry.missingDevices, [])
            XCTAssertEqual(entry.extraDevices, [])
            XCTAssertEqual(entry.staleDevices, [4, 5])
        }
    }

    func testSendMessageChallenge() async throws {
        do {
            _ = try await self.sendTestMessage(
                syncMessage: false,
                response: ChatResponse(
                    status: 428,
                    headers: ["content-type": "application/json"],
                    body: Data(
                        """
                        {
                            "token": "zzz",
                            "options": ["captcha"]
                        }
                        """.utf8
                    )
                )
            )
            XCTFail("should have thrown")
        } catch SignalError.rateLimitChallengeError(token: "zzz", options: let options, retryAfter: nil, message: _) {
            XCTAssertEqual(options, [ChallengeOption.captcha])
        }
    }
}

#endif
