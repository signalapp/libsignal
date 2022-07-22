//
// Copyright 2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import XCTest
import LibSignalClient

class Cds2Tests: TestCaseBase {

    // echo 92a47851c79f22f85ee1e164cc0963e35c8debc6c8bc1dafca235c79f801a57e | xxd -r -p | base64
    let mrenclave = Data(base64Encoded: "OdePF/iqmo6c2vFllZR6BXusIfAU0av9apmy39ThjR0=")!
    var attestationMessage = Data(repeating: 0, count: 0)
    let currentDate = Date(timeIntervalSince1970: 1655857680)

    override func setUp() {
        super.setUp()

        attestationMessage = try! Data(contentsOf: URL(fileURLWithPath: #file).deletingLastPathComponent().appendingPathComponent("Resources").appendingPathComponent("clienthandshakestart.data"))
    }

    func testCreateClient() {
        let cds2Client = try! Cds2Client(mrenclave: mrenclave, attestationMessage: attestationMessage, currentDate: currentDate)
        let initialMessage = cds2Client.initialRequest()
        XCTAssertEqual(48, initialMessage.count)
    }

    func testCreateClientFailsWithInvalidMrenclave() {
        let invalidMrenclave = Data(repeating: 0, count: 0)
        XCTAssertThrowsError(try Cds2Client(mrenclave: invalidMrenclave, attestationMessage: attestationMessage, currentDate: currentDate))
    }

    func testCreateClientFailsWithInvalidMessage() {
        let invalidMessage = Data(repeating: 0, count: 0)
        XCTAssertThrowsError(try Cds2Client(mrenclave: mrenclave, attestationMessage: invalidMessage, currentDate: currentDate))
    }

    func testEstablishedSendFailsPriorToEstablishment() {
        let cds2Client = try! Cds2Client(mrenclave: mrenclave, attestationMessage: attestationMessage, currentDate: currentDate)
        let receivedCiphertext: [UInt8] = [0x01, 0x02, 0x03]
        XCTAssertThrowsError(try cds2Client.establishedSend(receivedCiphertext))
    }

    func testEstablishedRecvFailsPriorToEstablishment() {
        let cds2Client = try! Cds2Client(mrenclave: mrenclave, attestationMessage: attestationMessage, currentDate: currentDate)
        let receivedCiphertext: [UInt8] = [0x01, 0x02, 0x03]
        XCTAssertThrowsError(try cds2Client.establishedRecv(receivedCiphertext))
    }
}
