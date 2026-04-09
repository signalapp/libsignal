//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import XCTest

@testable import LibSignalClient

// These testing endpoints aren"t generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class UnauthBackupsServiceUploadTests: UnauthChatServiceTestBase<any UnauthBackupsServiceImpl> {
    // These constants are from api/backups.rs
    static let TEST_CREDENTIAL = Data(
        base64Encoded:
            "AACkl2kAAAAAyQAAAAAAAAACAAAAAAAAAMUH8mZNP0qDpXFbK2e3dKL04Zw1UhyJ5ab+RlRLhAYELu5/fvwOhxzvxcnNGpqppkGOWc7SSN0kEU0MMIslejR+FDPRx0BWeRTeMmr2ngFVaHUjmazUmgCAPkr0BuLjShTidN9UW8r2M6FjodEtF/8="
    )!
    static let TEST_SERVER_KEYS = Data(
        base64Encoded:
            "AIRCHmMrkZXZ9ZuwKJkA0GeMOaDSdVsU26AghADhY3l5XBYwf0UCtm2tvvYsbnPgh9uIUyERm0Wg3v7pFtg+OEfsM6fwjdBFqAgfeqs1pT9nwp2Wp6oGdAfCTrGcqraXJoyAiwAh3vogu7ltucNKh25zKiOkIeIEJNrjbx2eEwkFnqLYuk/noxaOi2Zl7R5d7+vn0Me0d2AZhu0Uuk1vpTIuYf+X4UJXV/N5TYYxwOe/OQHu4zZmdaPjtPN1EHFJC5ALV+8BY9dN5ddS7iTL1uq1ksURAA9hAZzC9/aTr7J7"
    )!
    static let TEST_SIGNING_KEY = Data(
        base64Encoded:
            "KMhdmPEusAwoT3C2LzIbmGX6z+3HMbhgbrXmUwRfGF0="
    )!
    static let EXPECTED_PRESENTATION = Data(
        base64Encoded:
            "AMkAAAAAAAAAAgAAAAAAAAAApJdpAAAAAIoiVNK2DtZIRFCtQxRiSokkSiQEKrUm86QgMg+qyZZjLuJipcWuggZt6au2i4MOhslTP4qafDZUYWZnKdX7zV4MKW1+FqHVi9kns3+gGaHRCrUEqKcTBzZj/C79ZRJObwIAAAAAAAAA7vpvGr5uokinX1GRCgDr5au1ajuE2naAsAUXPXXpxTyKZo+S3m3OdyDUusIM3sIyUFwM1OeMtmHLgDcuGAqKdYAAAAAAAAAAcqkJSxGNgTB4ERB7Qcg8tp+IZnEhGxCzuvY3KqrjgwA1LniEMcZCO9kjcSL2Q5JS5yZYrv7Kkn0p3hY4vIrKBlgb0zycYLKRrUj+ndkHKJtWV/2xC42jehDUc1P2ufIEJfu4ScD+sUt9fgAV7uDsKI/ktXnhUPT7/ZxtCCp88gEU4nTfVFvK9jOhY6HRLRf/"
    )!
    static let EXPECTED_SIGNATURE = Data(
        base64Encoded:
            "TUmhLTMN7LLUOphZiAF8WZekmWzYDWlDiqNm3LirWwcSotw+yUd+MOizCpwVD+Wp9dLHjqU00xUwm+KnxtiKiA=="
    )!
    static let TEST_AUTH = BackupAuth(
        credential: try! BackupAuthCredential(contents: TEST_CREDENTIAL),
        serverKeys: try! GenericServerPublicParams(contents: TEST_SERVER_KEYS),
        signingKey: try! PrivateKey(TEST_SIGNING_KEY),
    )
    override class var selector: SelectorCheck { .backupsImpl }
    struct Function: Sendable {
        let impl:
            @Sendable (
                UInt64,
                Int64
            ) async throws -> UploadForm
        let endpoint: String
    }
    func functions() -> [Function] {
        let api = self.api
        return [
            Function(
                impl: {
                    uploadSize,
                    rngForTesting in
                    try await api
                        .getUploadFormImpl(
                            auth: Self.TEST_AUTH,
                            uploadSize: uploadSize,
                            rngForTesting: rngForTesting
                        )
                },
                endpoint: "/v1/archives/upload/form",
            ),
            Function(
                impl: {
                    uploadSize,
                    rngForTesting in
                    try await api
                        .getMediaUploadFormImpl(
                            auth: Self.TEST_AUTH,
                            uploadSize: uploadSize,
                            rngForTesting: rngForTesting
                        )
                },
                endpoint: "/v1/archives/media/upload/form",
            ),
        ]
    }
    func testReturnsDifferentValuesIfRngIsNotProvided() async throws {
        for f in self.functions() {
            async let _ =
                f
                .impl(
                    12345,
                    -1,
                )
            let (request1, request1Id) = try await fakeRemote.getNextIncomingRequest()
            async let _ =
                f
                .impl(
                    12345,
                    -1,
                )
            let (request2, request2Id) = try await fakeRemote.getNextIncomingRequest()
            XCTAssertNotEqual(request1.headers["x-signal-zk-auth"], request2.headers["x-signal-zk-auth"])
            try fakeRemote.sendResponse(requestId: request1Id, ChatResponse(status: 500))
            try fakeRemote.sendResponse(requestId: request2Id, ChatResponse(status: 500))
        }
    }
    func testSuccess() async throws {
        signal_testing_enable_deterministic_rng_for_testing()
        for f in self.functions() {
            async let response = f.impl(
                12345,
                0,
            )
            let (request, requestId) = try await fakeRemote.getNextIncomingRequest()
            XCTAssertEqual(request.method, "GET")
            XCTAssertEqual(request.pathAndQuery, "\(f.endpoint)?uploadLength=12345")
            XCTAssertEqual(
                request.headers,
                [
                    "x-signal-zk-auth": Self.EXPECTED_PRESENTATION.base64EncodedString(),
                    "x-signal-zk-auth-signature": Self.EXPECTED_SIGNATURE.base64EncodedString(),
                ]
            )
            try fakeRemote
                .sendResponse(
                    requestId: requestId,
                    ChatResponse(
                        status: 200,
                        message: "OK",
                        headers: ["content-type": "application/json"],
                        body: Data(
                            """
                            {
                                "cdn": 123,
                                "key": "abcde",
                                "headers": {"one": "val1", "two": "val2"},
                                "signedUploadLocation": "http://example.org/upload"
                            }
                            """.utf8
                        )
                    )
                )
            let uploadForm = try await response
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
    }
    func testUploadTooLarge() async throws {
        for f in self.functions() {
            async let responseFuture = f.impl(
                12345,
                0,
            )
            let (_, requestId) = try await fakeRemote.getNextIncomingRequest()
            try fakeRemote.sendResponse(requestId: requestId, ChatResponse(status: 413, message: "Content Too Large"))
            do {
                _ = try await responseFuture
                XCTFail("Failed to throw")
            } catch SignalError.uploadTooLarge(_) {}
        }
    }
    func testUnauthorized() async throws {
        for f in self.functions() {
            async let responseFuture = f.impl(
                12345,
                0,
            )
            let (_, requestId) = try await fakeRemote.getNextIncomingRequest()
            try fakeRemote.sendResponse(requestId: requestId, ChatResponse(status: 403, message: "Forbidden"))
            do {
                _ = try await responseFuture
                XCTFail("Failed to throw")
            } catch SignalError.requestUnauthorized(_) {}
        }
    }
}

#endif
