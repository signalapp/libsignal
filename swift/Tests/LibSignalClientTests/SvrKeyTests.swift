//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import XCTest

@testable import LibSignalClient

final class SvrKeyTests: XCTestCase {
    func testDerivations() throws {
        // These known answers were taken from iOS' MasterKeyTest.testDerivedKeys.
        // See: https://github.com/signalapp/Signal-iOS/blob/265ee500/SignalServiceKit/tests/Account/MasterKeyTest.swift#L54

        let svrKey = try SvrKey(contents: Data(repeating: 0x2a, count: SvrKey.SIZE))

        XCTAssertEqual(
            svrKey.deriveRegistrationLock(),
            Data(fromHexString: "3a40e25812e6c20cca76a602451dd2bc7484553514438cade320c2aef54e10d1")!
        )
        XCTAssertEqual(
            svrKey.deriveRegistrationRecoveryPassword(),
            Data(fromHexString: "91f959cfee39676dedd028bc8bbbd1e91ffa6a42c57754d095fe8abe7f0d4f56")!
        )
        XCTAssertEqual(
            svrKey.deriveStorageServiceKey(),
            Data(fromHexString: "3f31b618172a9f8ad45e290788e6176736e6161d4ea0e8050f8553521f59c200")!
        )
        XCTAssertEqual(
            svrKey.deriveLoggingKey(),
            Data(fromHexString: "cd2a39f4857de4df3fe793d1de061bfa3dd63533c0a4ef79b3fa3eba2bf96e62")!
        )
    }
}
