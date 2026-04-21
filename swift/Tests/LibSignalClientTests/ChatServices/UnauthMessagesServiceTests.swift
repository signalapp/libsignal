//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

private let recipientUuid = UUID(uuidString: "4FCFE887-A600-40CD-9AB7-FD2A695E9981")!

// From `SERIALIZED_GROUP_SEND_TOKEN` in Rust.
private let testGroupSendToken =
    try! GroupSendFullToken(
        contents: Data(base64Encoded: "ABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABo5c+LAQAA")!,
    )

class UnauthMessagesServiceTests: UnauthChatServiceTestBase<any UnauthMessagesService> {
    override class var selector: SelectorCheck { .messages }

    private func sendTestMultiRecipientMessage(response: ChatResponse) async throws -> MultiRecipientMessageResponse {
        let api = self.api
        let testPayload = Data([1, 2, 3, 4])
        // swift-format-ignore: GroupNumericLiterals
        let timestamp: UInt64 = 1700000000000
        async let result =
            api.sendMultiRecipientMessage(
                testPayload,
                timestamp: timestamp,
                auth: .story,
                onlineOnly: false,
                urgent: true,
            )

        // Get the incoming request from the fake remote
        let (request, id) = try await fakeRemote.getNextIncomingRequest()

        XCTAssertEqual(request.method, "PUT")
        XCTAssertEqual(
            request.pathAndQuery,
            "/v1/messages/multi_recipient?ts=1700000000000&online=false&urgent=true&story=true"
        )
        XCTAssertEqual(request.headers, ["content-type": "application/vnd.signal-messenger.mrm"])
        XCTAssertEqual(request.body, testPayload)

        try fakeRemote.sendResponse(
            requestId: id,
            response
        )
        return try await result
    }

    func testSendMultiRecipientMessageSuccess() async throws {
        let response = try await self.sendTestMultiRecipientMessage(
            response: ChatResponse(
                status: 200,
                headers: ["content-type": "application/json"],
                body: Data(
                    """
                    {
                        "uuids404": ["\(recipientUuid)"]
                    }
                    """.utf8
                )
            )
        )

        XCTAssertEqual(response.unregisteredIds, [Aci(fromUUID: recipientUuid)])
    }

    func testSendMultiRecipientMessageUnauthorized() async throws {
        do {
            _ = try await self.sendTestMultiRecipientMessage(response: ChatResponse(status: 401))
            XCTFail("should have thrown")
        } catch SignalError.requestUnauthorized(_:) {
        }
    }

    func testSendMultiRecipientMessageMismatchedDevices() async throws {
        do {
            _ = try await self.sendTestMultiRecipientMessage(
                response: ChatResponse(
                    status: 409,
                    headers: ["content-type": "application/json"],
                    body: Data(
                        """
                        [
                            {
                                "uuid": "\(recipientUuid)",
                                "devices": {
                                    "missingDevices": [4, 5],
                                    "extraDevices": [40, 50]
                                }
                            }
                        ]
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

    func testSendMultiRecipientMessageStaleDevices() async throws {
        do {
            _ = try await self.sendTestMultiRecipientMessage(
                response: ChatResponse(
                    status: 410,
                    headers: ["content-type": "application/json"],
                    body: Data(
                        """
                        [
                            {
                                "uuid": "\(recipientUuid)",
                                "devices": {
                                    "staleDevices": [4, 5]
                                }
                            }
                        ]
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

    func testSendMultiRecipientMessageServerSideError() async throws {
        do {
            _ = try await self.sendTestMultiRecipientMessage(response: ChatResponse(status: 500))
            XCTFail("should have thrown")
        } catch SignalError.ioError(_:) {
        }
    }

    private func sendTestSealedMessage(
        auth: UserBasedSendAuth,
        expectedAuthHeader: (String, String)?,
        response: ChatResponse
    ) async throws {
        let api = self.api

        // swift-format-ignore: GroupNumericLiterals
        let timestamp: UInt64 = 1700000000000
        async let result: Void =
            api.sendMessage(
                to: Aci(fromUUID: recipientUuid),
                timestamp: timestamp,
                contents: [
                    SingleOutboundSealedSenderMessage(
                        deviceId: DeviceId(validating: 1)!,
                        registrationId: 11,
                        contents: Data([1, 2, 3])
                    ),
                    SingleOutboundSealedSenderMessage(
                        deviceId: DeviceId(validating: 2)!,
                        registrationId: 22,
                        contents: Data([4, 5, 6])
                    ),
                ],
                auth: auth,
                onlineOnly: false,
                urgent: true,
            )

        // Get the incoming request from the fake remote
        let (request, id) = try await fakeRemote.getNextIncomingRequest()

        XCTAssertEqual(request.method, "PUT")
        XCTAssertEqual(
            request.pathAndQuery,
            "/v1/messages/\(recipientUuid.uuidString.lowercased())" + (expectedAuthHeader == nil ? "?story=true" : "")
        )
        var expectedHeaders = ["content-type": "application/json"]
        if let (expectedHeaderName, expectedValue) = expectedAuthHeader {
            expectedHeaders[expectedHeaderName] = expectedValue
        }
        XCTAssertEqual(request.headers, expectedHeaders)
        guard let requestBody = try JSONSerialization.jsonObject(with: request.body) as? NSDictionary else {
            fatalError("request was not a JSON dictionary")
        }
        XCTAssertEqual(
            requestBody,
            [
                "messages": [
                    [
                        "type": 6,
                        "destinationDeviceId": 1,
                        "destinationRegistrationId": 11,
                        "content": "AQID",
                    ],
                    [
                        "type": 6,
                        "destinationDeviceId": 2,
                        "destinationRegistrationId": 22,
                        "content": "BAUG",
                    ],
                ],
                "online": false,
                "urgent": true,
                // swift-format-ignore: GroupNumericLiterals
                "timestamp": 1_700_000_000_000,
            ] as NSDictionary
        )

        try fakeRemote.sendResponse(
            requestId: id,
            response
        )
        try await result
    }

    func testSendMessageSuccess() async throws {
        for (auth, expectedAuthHeader) in [
            (UserBasedSendAuth.story, nil),
            (.accessKey(Data(repeating: 0x0a, count: 16)), ("unidentified-access-key", "CgoKCgoKCgoKCgoKCgoKCg==")),
            (
                .groupSend(testGroupSendToken),
                ("group-send-token", testGroupSendToken.serialize().base64EncodedString())
            ),
            (.unrestrictedUnauthenticatedAccess, ("unidentified-access-key", "AAAAAAAAAAAAAAAAAAAAAA==")),
        ] {
            try await self.sendTestSealedMessage(
                auth: auth,
                expectedAuthHeader: expectedAuthHeader,
                response: ChatResponse(
                    status: 200,
                    headers: ["content-type": "application/json"],
                    body: Data("{}".utf8)
                )
            )
        }
    }

    func testSendMessageUnauthorized() async throws {
        do {
            _ = try await self.sendTestSealedMessage(
                auth: .story,
                expectedAuthHeader: nil,
                response: ChatResponse(status: 401)
            )
            XCTFail("should have thrown")
        } catch SignalError.requestUnauthorized(_:) {
        }
    }

    func testSendMessageMismatchedDevices() async throws {
        do {
            _ = try await self.sendTestSealedMessage(
                auth: .story,
                expectedAuthHeader: nil,
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
            _ = try await self.sendTestSealedMessage(
                auth: .story,
                expectedAuthHeader: nil,
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
}

#endif
