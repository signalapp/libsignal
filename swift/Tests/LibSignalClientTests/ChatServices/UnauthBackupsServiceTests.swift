//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import XCTest

@testable import LibSignalClient

// These testing endpoints aren"t generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

// These constants are from api/backups.rs
private let TEST_CREDENTIAL = Data(
    base64Encoded:
        "AACkl2kAAAAAyQAAAAAAAAACAAAAAAAAAMUH8mZNP0qDpXFbK2e3dKL04Zw1UhyJ5ab+RlRLhAYELu5/fvwOhxzvxcnNGpqppkGOWc7SSN0kEU0MMIslejR+FDPRx0BWeRTeMmr2ngFVaHUjmazUmgCAPkr0BuLjShTidN9UW8r2M6FjodEtF/8="
)!
private let TEST_SERVER_KEYS = Data(
    base64Encoded:
        "AIRCHmMrkZXZ9ZuwKJkA0GeMOaDSdVsU26AghADhY3l5XBYwf0UCtm2tvvYsbnPgh9uIUyERm0Wg3v7pFtg+OEfsM6fwjdBFqAgfeqs1pT9nwp2Wp6oGdAfCTrGcqraXJoyAiwAh3vogu7ltucNKh25zKiOkIeIEJNrjbx2eEwkFnqLYuk/noxaOi2Zl7R5d7+vn0Me0d2AZhu0Uuk1vpTIuYf+X4UJXV/N5TYYxwOe/OQHu4zZmdaPjtPN1EHFJC5ALV+8BY9dN5ddS7iTL1uq1ksURAA9hAZzC9/aTr7J7"
)!
private let TEST_SIGNING_KEY = Data(
    base64Encoded:
        "KMhdmPEusAwoT3C2LzIbmGX6z+3HMbhgbrXmUwRfGF0="
)!
private let TEST_SIGNING_KEY_PUB = Data(
    base64Encoded:
        "BWp7eOx6q6IlijMPozln1bY34JoLFZhGu3PLDnn7hO9t"
)!
private let EXPECTED_PRESENTATION = Data(
    base64Encoded:
        "AMkAAAAAAAAAAgAAAAAAAAAApJdpAAAAAIoiVNK2DtZIRFCtQxRiSokkSiQEKrUm86QgMg+qyZZjLuJipcWuggZt6au2i4MOhslTP4qafDZUYWZnKdX7zV4MKW1+FqHVi9kns3+gGaHRCrUEqKcTBzZj/C79ZRJObwIAAAAAAAAA7vpvGr5uokinX1GRCgDr5au1ajuE2naAsAUXPXXpxTyKZo+S3m3OdyDUusIM3sIyUFwM1OeMtmHLgDcuGAqKdYAAAAAAAAAAcqkJSxGNgTB4ERB7Qcg8tp+IZnEhGxCzuvY3KqrjgwA1LniEMcZCO9kjcSL2Q5JS5yZYrv7Kkn0p3hY4vIrKBlgb0zycYLKRrUj+ndkHKJtWV/2xC42jehDUc1P2ufIEJfu4ScD+sUt9fgAV7uDsKI/ktXnhUPT7/ZxtCCp88gEU4nTfVFvK9jOhY6HRLRf/"
)!
private let EXPECTED_SIGNATURE = Data(
    base64Encoded:
        "TUmhLTMN7LLUOphZiAF8WZekmWzYDWlDiqNm3LirWwcSotw+yUd+MOizCpwVD+Wp9dLHjqU00xUwm+KnxtiKiA=="
)!
private let TEST_AUTH = BackupAuth(
    credential: try! BackupAuthCredential(contents: TEST_CREDENTIAL),
    serverKeys: try! GenericServerPublicParams(contents: TEST_SERVER_KEYS),
    signingKey: try! PrivateKey(TEST_SIGNING_KEY),
)

class UnauthBackupsServiceUploadTests: UnauthChatServiceTestBase<any UnauthBackupsServiceImpl> {
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
                            auth: TEST_AUTH,
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
                            auth: TEST_AUTH,
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
                    "x-signal-zk-auth": EXPECTED_PRESENTATION.base64EncodedString(),
                    "x-signal-zk-auth-signature": EXPECTED_SIGNATURE.base64EncodedString(),
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

class UnauthBackupsServiceTests: UnauthChatServiceTestBase<any UnauthBackupsServiceImpl> {
    override class var selector: SelectorCheck { .backupsImpl }

    private func testSimpleBackupRequestUnauthorized<Result>(
        requestName: String,
        expectedRequest: NSDictionary,
        responseName: String,
        sendRequest: @Sendable (any UnauthBackupsServiceImpl) async throws -> Result,
    ) async {
        do {
            _ = try await testSimpleGrpcRequest(
                requestName: requestName,
                expectedRequest: expectedRequest,
                responseName: responseName,
                // There's no rule that says all the failed authentication responses HAVE to have the same oneof field name.
                // But in practice they do.
                response: ["failedAuthentication": ["description": "bad auth"]],
                sendRequest: sendRequest
            )
            XCTFail("should have failed")
        } catch SignalError.requestUnauthorized(_:) {
            // expected
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }

    private func backupRequest(_ extraProps: [String: Any] = [:]) -> NSDictionary {
        let result: NSMutableDictionary = [
            "signedPresentation": [
                "presentation": EXPECTED_PRESENTATION.base64EncodedString(),
                "presentationSignature": EXPECTED_SIGNATURE.base64EncodedString(),
            ]
        ]
        result.addEntries(from: extraProps)
        return result
    }

    func testSetPublicKey() async throws {
        try await testSimpleGrpcRequest(
            requestName: "org.signal.chat.backup.SetPublicKeyRequest",
            expectedRequest: backupRequest(["publicKey": TEST_SIGNING_KEY_PUB.base64EncodedString()]),
            responseName: "org.signal.chat.backup.SetPublicKeyResponse",
            response: ["success": [:]],
        ) {
            try await $0.setBackupPublicKey(auth: TEST_AUTH, rngForTesting: 0)
        }
        await testSimpleBackupRequestUnauthorized(
            requestName: "org.signal.chat.backup.SetPublicKeyRequest",
            expectedRequest: backupRequest(["publicKey": TEST_SIGNING_KEY_PUB.base64EncodedString()]),
            responseName: "org.signal.chat.backup.SetPublicKeyResponse",
        ) {
            try await $0.setBackupPublicKey(auth: TEST_AUTH, rngForTesting: 0)
        }
    }

    func testGetCdnCredentials() async throws {
        let credentials = try await testSimpleGrpcRequest(
            requestName: "org.signal.chat.backup.GetCdnCredentialsRequest",
            expectedRequest: backupRequest(["cdn": 40]),
            responseName: "org.signal.chat.backup.GetCdnCredentialsResponse",
            response: ["cdnCredentials": ["headers": ["b": "bbb", "a": "aaa"]]],
        ) {
            try await $0.getBackupCdnCredentials(auth: TEST_AUTH, cdn: 40, rngForTesting: 0)
        }
        XCTAssertEqual(credentials.headers, ["a": "aaa", "b": "bbb"])

        await testSimpleBackupRequestUnauthorized(
            requestName: "org.signal.chat.backup.GetCdnCredentialsRequest",
            expectedRequest: backupRequest(["cdn": 40]),
            responseName: "org.signal.chat.backup.GetCdnCredentialsResponse",
        ) {
            try await $0.getBackupCdnCredentials(auth: TEST_AUTH, cdn: 40, rngForTesting: 0)
        }
    }

    func testGetSvrBCredentials() async throws {
        let credentials: Auth = try await testSimpleGrpcRequest(
            requestName: "org.signal.chat.backup.GetSvrBCredentialsRequest",
            expectedRequest: backupRequest(),
            responseName: "org.signal.chat.backup.GetSvrBCredentialsResponse",
            response: ["svrbCredentials": ["username": "user", "password": "pass"]],
        ) {
            try await $0.getBackupSvrBCredentials(auth: TEST_AUTH, rngForTesting: 0)
        }
        XCTAssertEqual(credentials.username, "user")
        XCTAssertEqual(credentials.password, "pass")

        await testSimpleBackupRequestUnauthorized(
            requestName: "org.signal.chat.backup.GetSvrBCredentialsRequest",
            expectedRequest: backupRequest(),
            responseName: "org.signal.chat.backup.GetSvrBCredentialsResponse",
        ) {
            try await $0.getBackupSvrBCredentials(auth: TEST_AUTH, rngForTesting: 0)
        }
    }

    func testRefresh() async throws {
        try await testSimpleGrpcRequest(
            requestName: "org.signal.chat.backup.RefreshRequest",
            expectedRequest: backupRequest(),
            responseName: "org.signal.chat.backup.RefreshResponse",
            response: ["success": [:]],
        ) {
            try await $0.refreshBackup(auth: TEST_AUTH, rngForTesting: 0)
        }

        await testSimpleBackupRequestUnauthorized(
            requestName: "org.signal.chat.backup.RefreshRequest",
            expectedRequest: backupRequest(),
            responseName: "org.signal.chat.backup.RefreshResponse",
        ) {
            try await $0.refreshBackup(auth: TEST_AUTH, rngForTesting: 0)
        }
    }

    func testDeleteAll() async throws {
        try await testSimpleGrpcRequest(
            requestName: "org.signal.chat.backup.DeleteAllRequest",
            expectedRequest: backupRequest(),
            responseName: "org.signal.chat.backup.DeleteAllResponse",
            response: ["success": [:]],
        ) {
            try await $0.backupDeleteAll(auth: TEST_AUTH, rngForTesting: 0)
        }

        await testSimpleBackupRequestUnauthorized(
            requestName: "org.signal.chat.backup.DeleteAllRequest",
            expectedRequest: backupRequest(),
            responseName: "org.signal.chat.backup.DeleteAllResponse",
        ) {
            try await $0.backupDeleteAll(auth: TEST_AUTH, rngForTesting: 0)
        }
    }

    func testCopyMedia() async throws {
        signal_testing_enable_deterministic_rng_for_testing()
        try await testGrpcCases(
            try NativeTestingNice.TESTING_CopyBackupMediaTests(),
            invoke: { (api, args: [BridgeCopyBackupMediaItem]) in
                let items = args.map {
                    CopyBackupMediaItem(
                        sourceAttachmentCdn: $0.sourceAttachmentCdn,
                        sourceKey: $0.sourceKey,
                        objectLength: UInt64(exactly: $0.objectLength)!,
                        mediaId: $0.mediaId,
                        encryptionKey: $0.encryptionKey
                    )
                }
                return try await api.copyBackupMedia(auth: TEST_AUTH, items: items, rngForTesting: 0)
                    .collectUntilError()
            },
            check: { (expected: [CopyBackupMediaOut], actual) in
                var (actualItems, maybeError) = try! actual.get()
                for nextExpected in expected {
                    switch nextExpected {
                    case .item(let nextItem):
                        let actualItem: CopyBackupMediaOutcome = actualItems.removeFirst()
                        XCTAssertEqual(CopyBackupMediaOutcome(nextItem), actualItem)
                    case .invalidDataInStream:
                        if case SignalError.networkProtocolError(_)? = maybeError {
                        } else {
                            XCTFail("expected error not seen: \(maybeError, default: "<none>")")
                        }
                    case .credentialRejected:
                        if case SignalError.requestUnauthorized(_)? = maybeError {
                        } else {
                            XCTFail("expected error not seen: \(maybeError, default: "<none>")")
                        }
                    case .credentialRejectedWithoutAppropriateServerInfo:
                        if case SignalError.networkProtocolError(_)? = maybeError {
                        } else {
                            XCTFail("expected error not seen: \(maybeError, default: "<none>")")
                        }
                    }
                }
                XCTAssertEqual(actualItems, [])
            }
        )
    }
}

extension CopyBackupMediaOutcome: Equatable {
    public static func == (lhs: CopyBackupMediaOutcome, rhs: CopyBackupMediaOutcome) -> Bool {
        lhs.mediaId == rhs.mediaId && lhs.result == rhs.result
    }
}
extension CopyBackupMediaOutcome.Result: Equatable {
    public static func == (lhs: CopyBackupMediaOutcome.Result, rhs: CopyBackupMediaOutcome.Result) -> Bool {
        switch (lhs, rhs) {
        case (.success(cdn: let lCdn), .success(cdn: let rCdn)): lCdn == rCdn
        case (.sourceNotFound, .sourceNotFound),
            (.wrongSourceLength, .wrongSourceLength),
            (.outOfSpace, .outOfSpace):
            true
        default: false
        }
    }
}

#endif
