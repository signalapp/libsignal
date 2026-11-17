//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class AuthProfilesServiceTests: AuthChatServiceTestBase<any AuthProfilesService> {
    override class var selector: SelectorCheck { .profiles }

    func testGetAvatarUploadFormLegacy() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GetAvatarUploadFormLegacyTests(),
            invoke: { api, args in
                try await api.getAvatarUploadFormLegacy(
                    aci: args.aci,
                    profileKey: args.profileKey,
                )
            },
            check: { expected, actual in
                XCTAssertEqual(expected, try actual.get())
            }
        )
    }
}
class AuthProfilesServiceImplTests: AuthChatServiceTestBase<AuthenticatedChatConnection> {
    override class var selector: SelectorCheck { .allAuthenticatedConnection }

    func testGetAvatarCredential() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GetAvatarCredentialTests(),
            invoke: { api, args in
                try await api.getAvatarCredentialImpl(
                    aci: args.aci,
                    keyPair: args.keyPair,
                    rotationId: args.rotationId,
                    serverPublicParams: args.serverPublicParams,
                    currentTimeSeconds: Date(timeIntervalSince1970: TimeInterval(args.currentTimeSeconds)),
                    rng: 0,
                )
            },
            check: { expected, actual in
                if let cred = expected {
                    XCTAssertEqual((try actual.get()).serialize(), cred.serialize())
                } else {
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.accountMissingZkCredentialKey(_) {
                    }
                }
            }
        )
    }
}

#endif
