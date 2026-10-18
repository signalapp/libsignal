//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class AuthDonationsServiceTests: AuthChatServiceTestBase<any AuthDonationsService> {
    override class var selector: SelectorCheck { .donations }

    func testRedeemDonationReceipt() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_RedeemDonationReceiptTests(),
            invoke: { api, args in
                try await api.redeemDonationReceipt(
                    args.presentation,
                    badgeVisibility: args.visibility,
                )
            },
            check: { expected, actual in
                switch expected {
                case .success:
                    try actual.get()
                case .invalidReceipt:
                    do {
                        try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.invalidReceipt(_) {}
                case .alreadyRedeemed:
                    do {
                        try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.receiptAlreadyRedeemed(_) {}
                case .unexpectedError(let contains):
                    do {
                        try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.networkProtocolError(let msg) {
                        XCTAssert(msg.contains(contains), "Expected to find '\(contains)' in '\(msg)'")
                    }
                }
            }
        )
    }

    func testCreateDonationPermits() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_CreateDonationPermitsTests(),
            invoke: { api, args in
                try await api.createDonationPermits(
                    requestContext: args.requestContext,
                    serverParams: ServerPublicParams(contents: args.serverParams.bytes),
                )
            },
            check: { (expected, actual: Result<[DonationPermit], any Error>) in
                switch expected {
                case .success(let expectedPermits):
                    let permits = try actual.get()
                    XCTAssertEqual(permits.map { $0.serialize() }, expectedPermits.map { $0.serialize() })
                case .unexpectedError(let contains):
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.networkProtocolError(let msg) {
                        XCTAssert(msg.contains(contains), "Expected to find '\(contains)' in '\(msg)'")
                    }
                }
            }
        )
    }
}

#endif
