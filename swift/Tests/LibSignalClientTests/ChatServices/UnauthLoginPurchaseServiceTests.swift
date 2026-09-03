//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class UnauthLoginPurchaseServiceTests: UnauthChatServiceTestBase<any UnauthLoginPurchaseService> {
    override class var selector: SelectorCheck { .loginPurchase }

    func testCreateLoginReceiptCredential() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_CreateLoginReceiptCredentialTests(),
            invoke: { api, args in
                try await api.createLoginReceiptCredential(
                    paymentProcessor: args.paymentProcessor,
                    purchaseIdentifier: args.purchaseIdentifier,
                    receiptCredentialRequestContext: args.receiptCredentialRequestContext,
                    serverParams: ServerPublicParams(contents: args.serverParams.bytes),
                    purchaseTime: args.purchaseTime,
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
                    } catch SignalError.ReceiptCredentialErrorPaymentRequired(
                        chargeFailure: let chargeFailure,
                        message: _,
                    ) {
                        if let chargeFailure = chargeFailure {
                            XCTAssertEqual(expected, .paymentRequired(chargeFailure: [chargeFailure]))
                        } else {
                            XCTAssertEqual(expected, .paymentRequired(chargeFailure: []))
                        }
                    } catch SignalError.ReceiptCredentialErrorPaymentNotFound(_) {
                        XCTAssertEqual(expected, .paymentNotFound)
                    } catch SignalError.ReceiptCredentialErrorPaymentStillProcessing(_) {
                        XCTAssertEqual(expected, .paymentStillProcessing)
                    } catch SignalError.ReceiptCredentialErrorReceiptAlreadyIssued(_) {
                        XCTAssertEqual(expected, .receiptAlreadyIssued)
                    }
                }
            }
        )
    }
}

#endif
