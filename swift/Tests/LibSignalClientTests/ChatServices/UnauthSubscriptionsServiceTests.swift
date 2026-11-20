//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class UnauthSubscriptionsServiceTests: UnauthChatServiceTestBase<any UnauthSubscriptionsService> {
    override class var selector: SelectorCheck { .subscriptions }

    func testGetReceiptCredential() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GetSubscriptionReceiptCredentialTests(),
            invoke: { api, args in
                try await api.getSubscriptionReceiptCredential(
                    subscriberId: args.subscriberId,
                    receiptCredentialRequestContext: args.receiptCredentialRequestContext,
                    serverParams: ServerPublicParams(contents: args.serverParams.bytes),
                )
            },
            check: { (expected, actual: Result<ReceiptCredential, any Error>) in
                switch expected {
                case .success(let expectedReceipt):
                    let receipt = try actual.get()
                    XCTAssertEqual(receipt.serialize(), expectedReceipt.serialize())
                case .unexpectedError(let contains):
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.networkProtocolError(let msg) {
                        XCTAssert(msg.contains(contains), "Expected to find \(contains) in \(msg)")
                    }
                case .explicitError(let expected):
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.receiptCredentialErrorPaymentRequired(
                        chargeFailure: let chargeFailure,
                        message: _,
                    ) {
                        if let chargeFailure = chargeFailure {
                            XCTAssertEqual(expected, .paymentRequired(chargeFailure: [chargeFailure]))
                        } else {
                            XCTAssertEqual(expected, .paymentRequired(chargeFailure: []))
                        }
                    } catch SignalError.receiptCredentialErrorPaymentNotFound(_) {
                        XCTAssertEqual(expected, .paymentNotFound)
                    } catch SignalError.receiptCredentialErrorPaymentStillProcessing(_) {
                        XCTAssertEqual(expected, .paymentStillProcessing)
                    } catch SignalError.receiptCredentialErrorReceiptAlreadyIssued(_) {
                        XCTAssertEqual(expected, .receiptAlreadyIssued)
                    }
                }
            }
        )
    }

    func testGetPurchaseProductConfiguration() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GetProductConfigurationTests(),
            invoke: { api, _ in
                try await api.getPurchaseProductConfiguration()
            },
            check: { expected, actual in
                XCTAssertEqual(expected, try actual.get())
            }
        )
    }
}

#endif
