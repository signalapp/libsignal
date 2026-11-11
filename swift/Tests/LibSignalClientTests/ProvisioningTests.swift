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
        let pubkeyBytes = secondary.publicKey.serialize()
        XCTAssertEqual(33, pubkeyBytes.count)
        XCTAssertEqual(0x05, pubkeyBytes.first)

        let message = Data("provision message".utf8)
        let envelope = try encryptProvisionMessage(
            secondaryPublicKey: ProvisioningPublicKey(pubkeyBytes),
            provisionMessage: message
        )
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
        let pubkeyBytes = RecvProvisionCiphertextState.generate().publicKey.serialize()
        var badVersion = pubkeyBytes
        badVersion[0] = 0x06
        for badKey in [pubkeyBytes.prefix(32), pubkeyBytes + [0], badVersion] {
            XCTAssertThrowsError(
                try encryptProvisionMessage(secondaryPublicKey: ProvisioningPublicKey(badKey), provisionMessage: [])
            ) {
                guard case SignalError.invalidKey(_) = $0 else {
                    XCTFail("wrong error: \($0)")
                    return
                }
            }
        }
    }
}
