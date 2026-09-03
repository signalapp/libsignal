//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest

@testable import LibSignalClient

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

class AuthStickersServiceTests: AuthChatServiceTestBase<any AuthStickersService> {
    override class var selector: SelectorCheck { .stickers }

    func testGetStickerUploadForms() async throws {
        try await testGrpcCases(
            try NativeTestingNice.TESTING_GetStickerUploadFormTests(),
            invoke: { api, args in
                try await api.getStickerUploadForms(numberOfStickers: Int(args))
            },
            check: { expected, actual in
                switch expected {
                case .success(let expected):
                    XCTAssertEqual(expected, try actual.get())
                case .invalid:
                    do {
                        _ = try actual.get()
                        XCTFail("Expected exception")
                    } catch SignalError.networkProtocolError(_) {}
                }
            }
        )
    }
}

#endif
