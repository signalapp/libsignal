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

    func testSetOneTimeKemPreKeys() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_SetOneTimeKemPreKeysTests(),
            invoke: { api, args in
                try await api.setOneTimeKemPreKeys(
                    identity: ServiceIdKind(rawValue: args.identity)!,
                    preKeys: args.preKeys.map {
                        PublicKemPreKey(
                            keyId: UInt32($0.id),
                            publicKey: try KEMPublicKey($0.key),
                            signature: $0.sig,
                        )
                    }
                )
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }

    func testSetSignedEcPreKey() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_SetSignedEcPreKeyTests(),
            invoke: { api, args in
                try await api.setSignedEcPreKey(
                    identity: ServiceIdKind(rawValue: args.identity)!,
                    preKey: PublicSignedEcPreKey(
                        keyId: UInt32(args.preKey.id),
                        publicKey: try PublicKey(args.preKey.key),
                        signature: args.preKey.sig,
                    )
                )
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }

    func testSetLastResortKemPreKey() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_SetLastResortKemPreKeyTests(),
            invoke: { api, args in
                try await api.setLastResortKemPreKey(
                    identity: ServiceIdKind(rawValue: args.identity)!,
                    preKey: PublicKemPreKey(
                        keyId: UInt32(args.preKey.id),
                        publicKey: try KEMPublicKey(args.preKey.key),
                        signature: args.preKey.sig,
                    )
                )
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }
}

#endif
