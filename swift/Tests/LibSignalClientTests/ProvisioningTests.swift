//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import LibSignalClient
import XCTest

class ProvisioningTests: TestCaseBase {
    func testRoundTrip() throws {
        let secondary = RecvProvisionCiphertextState.generate()
        let publicKey = secondary.publicKey
        XCTAssertEqual(33, publicKey.count)
        XCTAssertEqual(0x05, publicKey.first)

        let message = Data("provision message".utf8)
        let envelope = try encryptProvisionMessage(secondaryPublicKey: publicKey, provisionMessage: message)
        XCTAssertEqual(message, try secondary.decryptEnvelope(envelope))
    }

    func testWrongRecipient() throws {
        let secondary = RecvProvisionCiphertextState.generate()
        let other = RecvProvisionCiphertextState.generate()
        let envelope = try encryptProvisionMessage(
            secondaryPublicKey: secondary.publicKey,
            provisionMessage: [1, 2, 3]
        )
        XCTAssertThrowsError(try other.decryptEnvelope(envelope)) {
            guard case SignalError.invalidMessage(_) = $0 else {
                XCTFail("wrong error: \($0)")
                return
            }
        }
    }

    func testMalformedEnvelope() {
        let secondary = RecvProvisionCiphertextState.generate()
        for envelope in [Data([0xFF]), Data()] {
            XCTAssertThrowsError(try secondary.decryptEnvelope(envelope)) {
                guard case SignalError.invalidMessage(_) = $0 else {
                    XCTFail("wrong error: \($0)")
                    return
                }
            }
        }
    }

    func testBadPublicKey() {
        var publicKey = RecvProvisionCiphertextState.generate().publicKey
        XCTAssertThrowsError(
            try encryptProvisionMessage(secondaryPublicKey: publicKey.prefix(32), provisionMessage: [])
        ) {
            guard case SignalError.invalidType(_) = $0 else {
                XCTFail("wrong error: \($0)")
                return
            }
        }

        publicKey[0] = 0x06
        XCTAssertThrowsError(try encryptProvisionMessage(secondaryPublicKey: publicKey, provisionMessage: [])) {
            guard case SignalError.invalidMessage(_) = $0 else {
                XCTFail("wrong error: \($0)")
                return
            }
        }
    }
}
