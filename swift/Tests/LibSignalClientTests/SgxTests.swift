//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import LibSignalClient
import XCTest

class SgxTests: TestCaseBase {
    enum ServiceType {
        case svr2, cds2
    }

    let testCases = [
        (
            ServiceType.cds2,
            // echo 92a47851c79f22f85ee1e164cc0963e35c8debc6c8bc1dafca235c79f801a57e | xxd -r -p | base64
            Data(base64Encoded: "OdePF/iqmo6c2vFllZR6BXusIfAU0av9apmy39ThjR0=")!,
            readResource(forName: "cds2handshakestart.data"),
            Date(timeIntervalSince1970: 1_655_857_680)
        ),

        (
            ServiceType.svr2,
            // echo acb1973aa0bbbd14b3b4e06f145497d948fd4a98efc500fcce363b3b743ec482 | xxd -r -p | base64
            Data(base64Encoded: "rLGXOqC7vRSztOBvFFSX2Uj9SpjvxQD8zjY7O3Q+xII=")!,
            readResource(forName: "svr2handshakestart.data"),
            Date(timeIntervalSince1970: 1_709_245_753)
        ),
    ]

    static func build(serviceType: ServiceType, mrenclave: Data, attestationMessage: Data, currentDate: Date) throws -> SgxClient {
        switch serviceType {
        case .cds2:
            return try Cds2Client(mrenclave: mrenclave, attestationMessage: attestationMessage, currentDate: currentDate)
        case .svr2:
            return try Svr2Client(mrenclave: mrenclave, attestationMessage: attestationMessage, currentDate: currentDate)
        }
    }

    func testCreateClient() {
        for (serviceType, mrenclave, attestationMessage, currentDate) in self.testCases {
            let client = try! SgxTests.build(serviceType: serviceType, mrenclave: mrenclave, attestationMessage: attestationMessage, currentDate: currentDate)
            let initialMessage = client.initialRequest()
            XCTAssertEqual(48, initialMessage.count, String(describing: serviceType))
        }
    }

    func testCreateClientFailsWithInvalidMrenclave() {
        let invalidMrenclave = Data(repeating: 0, count: 0)
        for (serviceType, _, attestationMessage, currentDate) in self.testCases {
            XCTAssertThrowsError(
                try SgxTests.build(
                    serviceType: serviceType,
                    mrenclave: invalidMrenclave,
                    attestationMessage: attestationMessage,
                    currentDate: currentDate
                ), String(describing: serviceType)
            )
        }
    }

    func testCreateClientFailsWithInvalidMessage() {
        let invalidMessage = Data(repeating: 0, count: 0)
        for (serviceType, mrenclave, _, currentDate) in self.testCases {
            XCTAssertThrowsError(
                try SgxTests.build(
                    serviceType: serviceType,
                    mrenclave: mrenclave,
                    attestationMessage: invalidMessage,
                    currentDate: currentDate
                ), String(describing: serviceType)
            )
        }
    }

    func testEstablishedSendFailsPriorToEstablishment() throws {
        let plaintext: [UInt8] = [0x01, 0x02, 0x03]
        for (serviceType, mrenclave, attestationMsg, currentDate) in self.testCases {
            let client = try SgxTests.build(
                serviceType: serviceType,
                mrenclave: mrenclave,
                attestationMessage: attestationMsg,
                currentDate: currentDate
            )
            XCTAssertThrowsError(try client.establishedSend(plaintext), String(describing: serviceType))
        }
    }

    func testEstablishedRecvFailsPriorToEstablishment() throws {
        let receivedCiphertext: [UInt8] = [0x01, 0x02, 0x03]
        for (serviceType, mrenclave, attestationMsg, currentDate) in self.testCases {
            let client = try SgxTests.build(
                serviceType: serviceType,
                mrenclave: mrenclave,
                attestationMessage: attestationMsg,
                currentDate: currentDate
            )
            XCTAssertThrowsError(try client.establishedRecv(receivedCiphertext), String(describing: serviceType))
        }
    }
}
