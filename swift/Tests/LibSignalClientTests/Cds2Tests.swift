//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest
import LibSignalClient

class Cds2Tests: TestCaseBase {

    let mrenclave = Data(repeating: 1, count: 32)
    let caCert = Data(repeating: 2, count: 32)
    var attestationMessage = Data(repeating: 0, count: 0)
    let earliestValidDate = Date().addingTimeInterval(-TimeInterval(60 * 60 * 24))

    override func setUp() {
        super.setUp()

        attestationMessage = try! Data(contentsOf: URL(fileURLWithPath: #file).deletingLastPathComponent().appendingPathComponent("Resources").appendingPathComponent("clienthandshakestart.data"))
    }

    func testCreateClient() {
        let cds2Client = try! Cds2Client.create_NOT_FOR_PRODUCTION(mrenclave, trustedCaCertBytes: caCert, attestationMessage: attestationMessage, earliestValidDate: earliestValidDate)
        let initialMessage = cds2Client.initialRequest()
        XCTAssertEqual(48, initialMessage.count)
    }

    func testCreateClientFailsWithInvalidMrenclave() {
        let invalidMrenclave = Data(repeating: 0, count: 0)
        XCTAssertThrowsError(try Cds2Client.create_NOT_FOR_PRODUCTION(invalidMrenclave, trustedCaCertBytes: caCert, attestationMessage: attestationMessage, earliestValidDate: earliestValidDate))
    }

    func testCreateClientFailsWithInvalidCert() {
        let invalidCert = Data(repeating: 0, count: 0)
        XCTAssertThrowsError(try Cds2Client.create_NOT_FOR_PRODUCTION(mrenclave, trustedCaCertBytes: invalidCert, attestationMessage: attestationMessage, earliestValidDate: earliestValidDate))
    }

    func testCreateClientFailsWithInvalidMessage() {
        let invalidMessage = Data(repeating: 0, count: 0)
        XCTAssertThrowsError(try Cds2Client.create_NOT_FOR_PRODUCTION(mrenclave, trustedCaCertBytes: caCert, attestationMessage: invalidMessage, earliestValidDate: earliestValidDate))
    }

    func testEstablishedSendFailsPriorToEstablishment() {
        let cds2Client = try! Cds2Client.create_NOT_FOR_PRODUCTION(mrenclave, trustedCaCertBytes: caCert, attestationMessage: attestationMessage, earliestValidDate: earliestValidDate)
        let receivedCiphertext: [UInt8] = [0x01, 0x02, 0x03]
        XCTAssertThrowsError(try cds2Client.establishedSend(receivedCiphertext))
    }

    func testEstablishedRecvFailsPriorToEstablishment() {
        let cds2Client = try! Cds2Client.create_NOT_FOR_PRODUCTION(mrenclave, trustedCaCertBytes: caCert, attestationMessage: attestationMessage, earliestValidDate: earliestValidDate)
        let receivedCiphertext: [UInt8] = [0x01, 0x02, 0x03]
        XCTAssertThrowsError(try cds2Client.establishedRecv(receivedCiphertext))
    }
}
