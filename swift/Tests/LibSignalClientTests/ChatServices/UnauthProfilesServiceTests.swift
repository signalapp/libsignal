//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class UnauthProfilesServiceTests: UnauthChatServiceTestBase<any UnauthProfilesService> {
    override class var selector: SelectorCheck { .profiles }
    override var grpcOverrides: [String] {
        ["AccountsAnonymousCheckAccountExistence"]
    }

    func testAccountExists() async throws {
        let ACI = Aci(fromUUID: UUID(uuidString: "9d0652a3-dcc3-4d11-975f-74d61598733f")!)
        let PNI = Pni(fromUUID: UUID(uuidString: "796abedb-ca4e-4f18-8803-1fde5b921f9f")!)
        let api = self.api
        struct TestCase {
            var serviceId: ServiceId
            var found: Bool
        }
        for testCase in [
            TestCase(serviceId: ACI, found: true),
            TestCase(serviceId: PNI, found: true),
            TestCase(serviceId: ACI, found: false),
            TestCase(serviceId: PNI, found: false),
        ] {
            async let responseFuture = api.accountExists(testCase.serviceId)
            let (request, id) = try await fakeRemote.getNextIncomingRequest()
            XCTAssertEqual(request.method, "HEAD")
            XCTAssertEqual(request.pathAndQuery, "/v1/accounts/account/\(testCase.serviceId.serviceIdString)")
            try fakeRemote.sendResponse(requestId: id, ChatResponse(status: testCase.found ? 200 : 404))
            let resp = try await responseFuture
            XCTAssertEqual(resp, testCase.found)
        }
    }

    func testGetProfileKeyCredential() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GetProfileKeyCredentialTests(),
            invoke: { api, args in
                try await api.getProfileKeyCredential(
                    requestContext: args.profileKeyRequestContext,
                    serverParams: try ServerPublicParams(contents: args.serverParams.bytes)
                )
            },
            check: { expected, actual in
                switch expected {
                case .success(let credential):
                    XCTAssertEqual(try actual.get().serialize(), credential.serialize())
                case .unexpectedError(let contains):
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.networkProtocolError(let message) {
                        XCTAssert(message.contains(contains))
                    }
                case .explicitError(.authFailed):
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.requestUnauthorized(_) {}
                case .explicitError(.profileNotFound):
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.profileNotFound(_) {}
                }
            }
        )

    }

    func testExtendAvatarTtl() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_ExtendAvatarTtlTests(),
            invoke: { api, args in
                try await api.extendAvatarTtl(
                    credential: args,
                )
            },
            check: { expected, actual in
                switch expected {
                case .found(let url):
                    XCTAssertEqual(url, try actual.get())
                case .notFound:
                    XCTAssertEqual(nil, try actual.get())
                case .invalidCredentials:
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.invalidAvatarUploadCredentialPresentation(_) {
                    }
                }
            }
        )
    }

    func testDeleteAvatar() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_DeleteAvatarTests(),
            invoke: { api, args in
                try await api.deleteAvatar(
                    credential: args,
                )
            },
            check: { expected, actual in
                if expected {
                    try actual.get()
                } else {
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.invalidAvatarUploadCredentialPresentation(_) {
                    }
                }
            }
        )
    }

    func testGetAvatarUploadForm() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GetAvatarUploadFormTests(),
            invoke: { api, args in
                try await api.getAvatarUploadForm(
                    credential: args.credential,
                    uploadLength: args.uploadLength,
                )
            },
            check: { expected, actual in
                switch expected {
                case .invalidCredential:
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.invalidAvatarUploadCredentialPresentation(_) {
                    }
                case .success(let form):
                    XCTAssertEqual(form, try actual.get())
                }
            }
        )
    }

    func testGetProfile() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_UnauthGetProfileTests(),
            invoke: { api, args in
                let inner = args.inner
                return try await api.getProfile(
                    aci: inner.aci,
                    profileKey: inner.profileKey,
                    auth: args.auth,
                    etag: inner.etag,
                    avatarCdnUrlValidationConfig: try AvatarCdnUrlValidationConfig.fromUrlPrefixes(
                        args.inner.avatarCdnConfigValidUrls
                    )
                )
            },
            check: { expected, actual in
                switch expected {
                case .failure(let err):
                    switch err {
                    case .profileDecodeError(_):
                        do {
                            _ = try actual.get()
                            XCTFail("Expected exception")
                        } catch SignalError.profileCantBeDecoded(_) {
                        }
                    case .profileNotFound:
                        do {
                            _ = try actual.get()
                            XCTFail("Expected exception")
                        } catch SignalError.profileNotFound(_) {
                        }
                    case .failedUnidentifiedAuthorization:
                        do {
                            _ = try actual.get()
                            XCTFail("Expected exception")
                        } catch SignalError.requestUnauthorized(_) {
                        }
                    }
                case .success(let fetchedProfile):
                    XCTAssertEqual(fetchedProfile, try actual.get())
                }
            }
        )
    }
}

#endif
