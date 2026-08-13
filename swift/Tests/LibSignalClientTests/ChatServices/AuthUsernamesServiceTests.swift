//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class AuthUsernamesServiceTests: AuthChatServiceTestBase<any AuthUsernamesService> {
    override class var selector: SelectorCheck { .usernames }

    func testReserveUsernameHash() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_ReserveUsernameHashTests(),
            invoke: { api, args in
                try await api.reserveUsernameHashes(args.usernames)
            },
            check: { expected, actual in
                switch expected {
                case .success(let username):
                    XCTAssertEqual(try actual.get(), username)
                case .usernameNotAvailable:
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.usernameNotAvailable(_) {}
                }
            }
        )
    }

    func testSetUsernameLink() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_SetUsernameLinkTests(),
            invoke: { api, args in
                try await api.setUsernameLink(
                    usernameCiphertext: args.usernameCiphertext,
                    keepLinkHandle: args.keepLinkHandle,
                )
            },
            check: { expected, actual in
                switch expected {
                case .success(let username):
                    XCTAssertEqual(try actual.get(), username)
                case .usernameNotSet:
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.usernameNotSet(_) {}
                }
            }
        )
    }

    func testDeleteUsernameHash() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_DeleteUsernameHashTests(),
            invoke: { api, _ in
                try await api.deleteUsernameHash()
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }

    func testDeleteUsernameLink() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_DeleteUsernameLinkTests(),
            invoke: { api, _ in
                try await api.deleteUsernameLink()
            },
            check: { _, actual in
                try actual.get()
            }
        )
    }
}

// Uses the internal Impl protocol so the test can pin the RNG seed; the public
// confirmUsername(_:usernameCiphertext:) simply forwards with an OS-random RNG.
class AuthUsernamesServiceImplTests: AuthChatServiceTestBase<any AuthUsernamesServiceImpl> {
    override class var selector: SelectorCheck { .usernamesImpl }

    func testConfirmUsername() async throws {
        signal_testing_enable_deterministic_rng_for_testing()
        try await testGrpcCases(
            try NativeTestingNice.TESTING_ConfirmUsernameTests(),
            invoke: { api, args in
                try await api.confirmUsername(
                    try Username(args.username),
                    usernameCiphertext: args.usernameCiphertext,
                    rngForTesting: 0,
                )
            },
            check: { expected, actual in
                switch expected {
                case .success(let linkHandle):
                    XCTAssertEqual(try actual.get(), linkHandle)
                case .reservationNotFound:
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.usernameReservationNotFound(_) {}
                case .usernameNotAvailable:
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.usernameNotAvailable(_) {}
                }
            }
        )
    }
}

#endif
