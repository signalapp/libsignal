//
// Copyright 2025 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class UnauthUsernamesServiceTests: UnauthChatServiceTestBase<any UnauthUsernamesService> {
    override class var selector: SelectorCheck { .usernames }

    static let EXPECTED_USERNAME = "moxie.01"
    static let ENCRYPTED_USERNAME =
        "kj5ah-VbEgjpfJsNt-Wto2H626DRmJSVpYPy0yPOXA8kiSFkBCD8ysFlJ-Z3MhiAnt_R3Nm7ZY0W5fiRDLVbhaE2z-KO2xdf5NcVbkewCzhvveecS3hHskDp1aSfbvwTZNNGPmAuKWvJ1MPdHzsF0w"
    static let ENCRYPTED_USERNAME_ENTROPY = Data(
        fromHexString: "4302c613c092a51c5394becffeb6f697300a605348e93f03c3db95e0b03d28f1"
    )!

    func testUsernameHashLookup() async throws {
        let api = self.api
        async let responseFuture = api.lookUpUsernameHash(Data([1, 2, 3, 4]))

        let (request, id) = try await fakeRemote.getNextIncomingRequest()
        XCTAssertEqual(request.method, "GET")

        let uuid = UUID(uuidString: "4FCFE887-A600-40CD-9AB7-FD2A695E9981")!

        try fakeRemote.sendResponse(
            requestId: id,
            ChatResponse(
                status: 200,
                headers: ["content-type": "application/json"],
                body: Data(
                    """
                    {
                        "uuid": "\(uuid)"
                    }
                    """.utf8
                )
            )
        )

        let responseFromServer = try await responseFuture
        XCTAssertEqual(responseFromServer, Aci(fromUUID: uuid))
    }

    func testUsernameHashLookupMissing() async throws {
        let api = self.api
        async let responseFuture = api.lookUpUsernameHash(Data([1, 2, 3, 4]))

        let (request, id) = try await fakeRemote.getNextIncomingRequest()
        XCTAssertEqual(request.method, "GET")

        try fakeRemote.sendResponse(
            requestId: id,
            ChatResponse(status: 404)
        )

        let responseFromServer = try await responseFuture
        XCTAssertNil(responseFromServer)
    }

    func testUsernameHashChallengeError() async throws {
        let api = self.api
        async let responseFuture = api.lookUpUsernameHash(Data([1, 2, 3, 4]))

        let (request, id) = try await fakeRemote.getNextIncomingRequest()
        XCTAssertEqual(request.method, "GET")

        try fakeRemote.sendResponse(
            requestId: id,
            ChatResponse(
                status: 428,
                headers: ["content-type": "application/json"],
                body: Data(
                    """
                    {
                        "token": "not-legal-tender",
                        "options": ["pushChallenge"]
                    }
                    """.utf8
                )
            )
        )

        do {
            _ = try await responseFuture
            XCTFail("should have failed")
        } catch SignalError.rateLimitChallengeError(let token, let options, _) {
            XCTAssertEqual(token, "not-legal-tender")
            XCTAssertEqual(options, [.pushChallenge])
        }
    }

    func testUsernameHashServerSideError() async throws {
        let api = self.api
        async let responseFuture = api.lookUpUsernameHash(Data([1, 2, 3, 4]))

        let (request, id) = try await fakeRemote.getNextIncomingRequest()
        XCTAssertEqual(request.method, "GET")

        try fakeRemote.sendResponse(
            requestId: id,
            ChatResponse(status: 500)
        )

        do {
            _ = try await responseFuture
            XCTFail("should have failed")
        } catch SignalError.networkProtocolError(_) {
        }
    }

    func testUsernameLinkLookup() async throws {
        let api = self.api
        async let responseFuture = api.lookUpUsernameLink(UUID(uuid: nilUuid), entropy: Self.ENCRYPTED_USERNAME_ENTROPY)

        let (request, id) = try await fakeRemote.getNextIncomingRequest()
        XCTAssertEqual(request.method, "GET")
        XCTAssertEqual(request.pathAndQuery, "/v1/accounts/username_link/00000000-0000-0000-0000-000000000000")

        try fakeRemote.sendResponse(
            requestId: id,
            ChatResponse(
                status: 200,
                headers: ["content-type": "application/json"],
                body: Data(
                    """
                    {
                        "usernameLinkEncryptedValue": "\(Self.ENCRYPTED_USERNAME)"
                    }
                    """.utf8
                )
            )
        )

        let responseFromServer = try await responseFuture
        XCTAssertNotNil(responseFromServer)
        XCTAssertEqual(responseFromServer!.value, Self.EXPECTED_USERNAME)
    }

    func testUsernameLinkLookupMissing() async throws {
        let api = self.api
        async let responseFuture = api.lookUpUsernameLink(UUID(uuid: nilUuid), entropy: Self.ENCRYPTED_USERNAME_ENTROPY)

        let (request, id) = try await fakeRemote.getNextIncomingRequest()
        XCTAssertEqual(request.method, "GET")
        XCTAssertEqual(request.pathAndQuery, "/v1/accounts/username_link/00000000-0000-0000-0000-000000000000")

        try fakeRemote.sendResponse(
            requestId: id,
            ChatResponse(status: 404)
        )

        let responseFromServer = try await responseFuture
        XCTAssertNil(responseFromServer)
    }

    func testUsernameLinkGarbageCiphertext() async throws {
        let api = self.api
        async let responseFuture = api.lookUpUsernameLink(UUID(uuid: nilUuid), entropy: Self.ENCRYPTED_USERNAME_ENTROPY)

        let (request, id) = try await fakeRemote.getNextIncomingRequest()
        XCTAssertEqual(request.method, "GET")
        XCTAssertEqual(request.pathAndQuery, "/v1/accounts/username_link/00000000-0000-0000-0000-000000000000")

        try fakeRemote.sendResponse(
            requestId: id,
            ChatResponse(
                status: 200,
                headers: ["content-type": "application/json"],
                body: Data(
                    """
                    {
                        "usernameLinkEncryptedValue": "\(Self.ENCRYPTED_USERNAME)A"
                    }
                    """.utf8
                )
            )
        )

        do {
            _ = try await responseFuture
            XCTFail("should have failed")
        } catch SignalError.usernameLinkInvalid(_) {
        }
    }

    func testUsernameLinkServerSideError() async throws {
        let api = self.api
        async let responseFuture = api.lookUpUsernameLink(UUID(uuid: nilUuid), entropy: Self.ENCRYPTED_USERNAME_ENTROPY)

        let (request, id) = try await fakeRemote.getNextIncomingRequest()
        XCTAssertEqual(request.method, "GET")
        XCTAssertEqual(request.pathAndQuery, "/v1/accounts/username_link/00000000-0000-0000-0000-000000000000")

        try fakeRemote.sendResponse(
            requestId: id,
            ChatResponse(status: 500)
        )

        do {
            _ = try await responseFuture
            XCTFail("should have failed")
        } catch SignalError.networkProtocolError(_) {
        }
    }

    func testUsernameLinkBadEntropy() async throws {
        let api = self.api
        async let responseFuture = api.lookUpUsernameLink(
            UUID(uuid: nilUuid),
            entropy: Self.ENCRYPTED_USERNAME_ENTROPY.dropFirst()
        )

        do {
            _ = try await responseFuture
            XCTFail("should have failed")
        } catch SignalError.usernameLinkInvalidEntropyDataLength(_) {
        }
    }
}

#endif
