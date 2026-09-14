//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class AuthKeysServiceTests: AuthChatServiceTestBase<any AuthKeysService> {
    override class var selector: SelectorCheck { .keys }

    func testGetPreKeyCount() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GetPreKeyCountTests(),
            invoke: { api, _ in
                try await api.getPreKeyCount()
            },
            check: { expected, actual in
                XCTAssertEqual(PreKeyCounts.fromInternal(expected), try actual.get())
            }
        )
    }

    func testSetOneTimeEcPreKeys() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_SetOneTimeEcPreKeysTests(),
            invoke: { api, args in
                try await api.setOneTimeEcPreKeys(
                    identity: ServiceIdKind(rawValue: args.identity)!,
                    preKeys: args.preKeys.map {
                        PublicEcPreKey(
                            keyId: UInt32($0.0),
                            publicKey: try PublicKey($0.1)
                        )
                    }
                )
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }
}

#endif
