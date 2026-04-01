//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

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
}

#endif
