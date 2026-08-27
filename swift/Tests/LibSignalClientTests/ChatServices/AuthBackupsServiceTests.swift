//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class AuthBackupsServiceTests: AuthChatServiceTestBase<any AuthBackupsService> {
    override class var selector: SelectorCheck { .backups }

    func testRedeemReceipt() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_RedeemBackupReceiptTests(),
            invoke: { api, args in
                try await api.redeemBackupReceipt(try! .init(contents: args))
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
                case .missingBackupId:
                    do {
                        try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.missingBackupId(_) {}
                case .missingResponse:
                    do {
                        try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.networkProtocolError(_) {}
                }
            }
        )
    }
}

#endif
