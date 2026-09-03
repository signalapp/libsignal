//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class AuthAccountsServiceTests: AuthChatServiceTestBase<any AuthAccountsService> {
    override class var selector: SelectorCheck { .accounts }

    func testDeleteAccount() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_DeleteAccountTests(),
            invoke: { api, _ in
                try await api.deleteAccount()
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }

    func testSetRegistrationLock() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_SetRegistrationLockTests(),
            invoke: { api, svrKey in
                try await api.setRegistrationLock(SvrKey(contents: svrKey))
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }

    func testClearRegistrationLock() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_ClearRegistrationLockTests(),
            invoke: { api, _ in
                try await api.clearRegistrationLock()
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }

    func testSetRegistrationRecoveryPassword() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_SetRegistrationRecoveryPasswordTests(),
            invoke: { api, svrKey in
                try await api.setRegistrationRecoveryPassword(SvrKey(contents: svrKey))
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }

    func testSetDiscoverableByPhoneNumber() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_SetDiscoverableByPhoneNumberTests(),
            invoke: { api, discoverable in
                try await api.setDiscoverableByPhoneNumber(discoverable)
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }

    func testGenerateTotpKey() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GenerateTotpKeyTests(),
            invoke: { api, _ in
                try await api.generateTotpKey()
            },
            check: { expected, actual in
                switch expected {
                case .success(let pendingKey):
                    XCTAssertEqual(try actual.get(), PendingTotpKey.fromInternal(pendingKey))
                case .tooManyTotpKeys:
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.tooManyTotpKeys(_) {}
                case .tooManyMfaKeys:
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.tooManyMfaKeys(_) {}
                }
            }
        )
    }

    func testListMfaKeys() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_ListMfaKeysTests(),
            invoke: { api, args in
                try await api.listMfaKeys(svrKey: SvrKey(contents: args.svrKey))
            },
            check: { expected, actual in
                switch expected {
                case .success(let keys):
                    let actualKeys = try actual.get()
                    XCTAssertEqual(actualKeys, keys.map { ConfirmedMfaKey.fromInternal($0) })
                    for (expectedKey, actualKey) in zip(keys, actualKeys) {
                        switch expectedKey.metadata {
                        case .metadata(let metadata):
                            XCTAssertEqual(actualKey.metadata?.name, metadata.name)
                            XCTAssertEqual(actualKey.metadata?.createdAt, metadata.createdAt)
                        case .unreadable:
                            XCTAssertNil(actualKey.metadata)
                        }
                        switch expectedKey.kind {
                        case .totp: XCTAssertEqual(actualKey.kind, .totp)
                        case .unknown: XCTAssertEqual(actualKey.kind, .unknown)
                        }
                    }
                }
            }
        )
    }

    func testTotpKeyNameInvalid() async throws {
        for invalidName in [
            String(repeating: "a", count: MfaMetadata.nameMaxLength + 1),
            "before\0after",
        ] {
            let metadata = MfaMetadata(
                name: invalidName,
                createdAt: Date(timeIntervalSince1970: 0),
            )
            do {
                _ = try await api.confirmTotpKey(
                    oneTimePassword: 123_456,
                    metadata: metadata,
                    svrKey: SvrKey(contents: Data(repeating: 0, count: 32))
                )
                XCTFail("Expected exception")
            } catch SignalError.invalidArgument(_) {}
            do {
                try await api.setMfaKeyMetadata(
                    for: 0,
                    metadata: metadata,
                    svrKey: SvrKey(contents: Data(repeating: 0, count: 32))
                )
                XCTFail("Expected exception")
            } catch SignalError.invalidArgument(_) {}
        }
    }

    func testTotpKeyCreatedAtUnrepresentable() async throws {
        let invalidDates = [
            Date(timeIntervalSince1970: -1),
            Date(timeIntervalSince1970: -0.0005),
            Date(timeIntervalSince1970: .nan),
            Date(timeIntervalSince1970: .infinity),
            Date(timeIntervalSince1970: Double(UInt64.max)),
        ]
        let svrKey = try SvrKey(contents: Data(repeating: 0, count: 32))

        for createdAt in invalidDates {
            let metadata = MfaMetadata(name: "test", createdAt: createdAt)
            do {
                _ = try await api.confirmTotpKey(
                    oneTimePassword: 123_456,
                    metadata: metadata,
                    svrKey: svrKey
                )
                XCTFail("Expected exception")
            } catch SignalError.invalidArgument(_) {}

            do {
                try await api.setMfaKeyMetadata(for: 0, metadata: metadata, svrKey: svrKey)
                XCTFail("Expected exception")
            } catch SignalError.invalidArgument(_) {}
        }
    }

    func testMfaKeyIdOutOfRange() async throws {
        // 128 is the first ID past the server's range; the others don't even fit in the bridge.
        for badId in [128, Int(Int32.max) + 1, -1] {
            do {
                try await api.removeMfaKey(id: badId)
                XCTFail("Expected exception for \(badId)")
            } catch SignalError.invalidArgument(_) {}
        }
    }

    func testOneTimePasswordTooLarge() async throws {
        do {
            _ = try await api.confirmTotpKey(
                oneTimePassword: Int(Int32.max) + 1,
                metadata: MfaMetadata(name: "ok", createdAt: Date(timeIntervalSince1970: 0)),
                svrKey: SvrKey(contents: Data(repeating: 0, count: 32))
            )
            XCTFail("Expected exception")
        } catch SignalError.invalidArgument(_) {}
    }

    func testRemoveMfaKey() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_RemoveMfaKeyTests(),
            invoke: { api, args in
                try await api.removeMfaKey(id: Int(args.keyId))
            },
            check: { expected, actual in
                switch expected {
                case .success:
                    try actual.get()
                }
            }
        )
    }
}

// Uses the internal Impl protocol so the test can pin the RNG seed; the public methods simply
// forward with an OS-random RNG.
class AuthAccountsServiceImplTests: AuthChatServiceTestBase<any AuthAccountsServiceImpl> {
    override class var selector: SelectorCheck { .accountsImpl }

    func testConfirmTotpKey() async throws {
        signal_testing_enable_deterministic_rng_for_testing()
        try await testGrpcCases(
            try NativeTestingNice.TESTING_ConfirmTotpKeyTests(),
            invoke: { api, args in
                try await api.confirmTotpKey(
                    oneTimePassword: Int(args.oneTimePassword),
                    metadata: MfaMetadata(name: args.name, createdAt: args.createdAt),
                    svrKey: SvrKey(contents: args.svrKey),
                    rngForTesting: 0,
                )
            },
            check: { expected, actual in
                switch expected {
                case .success(let keyId):
                    XCTAssertEqual(try actual.get(), Int(keyId))
                case .oneTimePasswordNotVerified:
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.oneTimePasswordNotVerified(_) {}
                case .tooManyMfaKeys:
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.tooManyMfaKeys(_) {}
                }
            }
        )
    }

    func testSetMfaKeyMetadata() async throws {
        signal_testing_enable_deterministic_rng_for_testing()
        try await testGrpcCases(
            try NativeTestingNice.TESTING_SetMfaKeyMetadataTests(),
            invoke: { api, args in
                try await api.setMfaKeyMetadata(
                    for: Int(args.keyId),
                    metadata: MfaMetadata(name: args.name, createdAt: args.createdAt),
                    svrKey: SvrKey(contents: args.svrKey),
                    rngForTesting: 0,
                )
            },
            check: { expected, actual in
                switch expected {
                case .success:
                    try actual.get()
                case .keyNotFound:
                    do {
                        try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.mfaKeyNotFound(_) {}
                }
            }
        )
    }
}

#endif
