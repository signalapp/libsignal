//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

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
        let uuid = UUID(uuidString: "4FCFE887-A600-40CD-9AB7-FD2A695E9981")!

        let response = try await self.sendTestMultiRecipientMessage(
            response: ChatResponse(
                status: 200,
                headers: ["content-type": "application/json"],
                body: Data(
                    """
                    {
                        "uuids404": ["\(uuid)"]
                    }
                    """.utf8
                )
            )
        )

        XCTAssertEqual(response.unregisteredIds, [Aci(fromUUID: uuid)])
    }

    func testSendMultiRecipientMessageUnauthorized() async throws {
        do {
            _ = try await self.sendTestMultiRecipientMessage(response: ChatResponse(status: 401))
            XCTFail("should have thrown")
        } catch SignalError.requestUnauthorized(_:) {
        }
    }

    func testSendMultiRecipientMessageMismatchedDevices() async throws {
        let uuid = UUID(uuidString: "4FCFE887-A600-40CD-9AB7-FD2A695E9981")!

        do {
            _ = try await self.sendTestMultiRecipientMessage(
                response: ChatResponse(
                    status: 409,
                    headers: ["content-type": "application/json"],
                    body: Data(
                        """
                        [
                            {
                                "uuid": "\(uuid)",
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
            XCTAssertEqual(entry.account, Aci(fromUUID: uuid))
            XCTAssertEqual(entry.missingDevices, [4, 5])
            XCTAssertEqual(entry.extraDevices, [40, 50])
            XCTAssertEqual(entry.staleDevices, [])
        }
    }

    func testSendMultiRecipientMessageStaleDevices() async throws {
        let uuid = UUID(uuidString: "4FCFE887-A600-40CD-9AB7-FD2A695E9981")!

        do {
            _ = try await self.sendTestMultiRecipientMessage(
                response: ChatResponse(
                    status: 410,
                    headers: ["content-type": "application/json"],
                    body: Data(
                        """
                        [
                            {
                                "uuid": "\(uuid)",
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
            XCTAssertEqual(entry.account, Aci(fromUUID: uuid))
            XCTAssertEqual(entry.missingDevices, [])
            XCTAssertEqual(entry.extraDevices, [])
            XCTAssertEqual(entry.staleDevices, [4, 5])
        }
    }

    func testSendMultiRecipientMessageServerSideError() async throws {
        do {
            _ = try await self.sendTestMultiRecipientMessage(response: ChatResponse(status: 500))
            XCTFail("should have thrown")
        } catch SignalError.networkProtocolError(_:) {
        }
    }
}

#endif
