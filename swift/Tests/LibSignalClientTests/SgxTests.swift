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
            SgxTests.readResource(forName: "cds2handshakestart.data"),
            Date(timeIntervalSince1970: 1_655_857_680)
        ),

        (
            ServiceType.svr2,
            // echo a8a261420a6bb9b61aa25bf8a79e8bd20d7652531feb3381cbffd446d270be95 | xxd -r -p | base64
            Data(base64Encoded: "qKJhQgprubYaolv4p56L0g12UlMf6zOBy//URtJwvpU=")!,
            SgxTests.readResource(forName: "svr2handshakestart.data"),
            Date(timeIntervalSince1970: 1_683_836_600)
        ),
    ]

    static func readResource(forName name: String) -> Data {
        try! Data(
            contentsOf: URL(fileURLWithPath: #file)
                .deletingLastPathComponent()
                .appendingPathComponent("Resources")
                .appendingPathComponent(name))
    }

    static func build(serviceType: ServiceType, mrenclave: Data, attestationMessage: Data, currentDate: Date) throws -> SgxClient {
        switch serviceType {
        case .cds2:
            return try Cds2Client(mrenclave: mrenclave, attestationMessage: attestationMessage, currentDate: currentDate)
        case .svr2:
            return try Svr2Client(mrenclave: mrenclave, attestationMessage: attestationMessage, currentDate: currentDate)
        }
    }

    func testCreateClient() {
        for (serviceType, mrenclave, attestationMessage, currentDate) in testCases {
            let client = try! SgxTests.build(serviceType: serviceType, mrenclave: mrenclave, attestationMessage: attestationMessage, currentDate: currentDate)
            let initialMessage = client.initialRequest()
            XCTAssertEqual(48, initialMessage.count, String(describing: serviceType))
        }
    }

    func testCreateClientFailsWithInvalidMrenclave() {
        let invalidMrenclave = Data(repeating: 0, count: 0)
        for (serviceType, _, attestationMessage, currentDate) in testCases {
            XCTAssertThrowsError(
                try SgxTests.build(
                    serviceType: serviceType,
                    mrenclave: invalidMrenclave,
                    attestationMessage: attestationMessage,
                    currentDate: currentDate), String(describing: serviceType))
        }
    }

    func testCreateClientFailsWithInvalidMessage() {
        let invalidMessage = Data(repeating: 0, count: 0)
        for (serviceType, mrenclave, _, currentDate) in testCases {
            XCTAssertThrowsError(
                try SgxTests.build(
                    serviceType: serviceType,
                    mrenclave: mrenclave,
                    attestationMessage: invalidMessage,
                    currentDate: currentDate), String(describing: serviceType))
        }
    }

    func testEstablishedSendFailsPriorToEstablishment() {
        let plaintext: [UInt8] = [0x01, 0x02, 0x03]
        for (serviceType, mrenclave, attestationMsg, currentDate) in testCases {
            let client = try! SgxTests.build(
                serviceType: serviceType,
                mrenclave: mrenclave,
                attestationMessage: attestationMsg,
                currentDate: currentDate)
            XCTAssertThrowsError(try client.establishedSend(plaintext), String(describing: serviceType))
        }
    }

    func testEstablishedRecvFailsPriorToEstablishment() {
        let receivedCiphertext: [UInt8] = [0x01, 0x02, 0x03]
        for (serviceType, mrenclave, attestationMsg, currentDate) in testCases {
            let client = try! SgxTests.build(
                serviceType: serviceType,
                mrenclave: mrenclave,
                attestationMessage: attestationMsg,
                currentDate: currentDate)
            XCTAssertThrowsError(try client.establishedRecv(receivedCiphertext), String(describing: serviceType))
        }
    }
}
