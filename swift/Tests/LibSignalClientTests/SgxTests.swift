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
            // echo f25dfd3b18adc4c0dc190bae1edd603ceca81b42a10b1de52f74db99b338619e | xxd -r -p | base64
            Data(base64Encoded: "8l39OxitxMDcGQuuHt1gPOyoG0KhCx3lL3TbmbM4YZ4=")!,
            SgxTests.readResource(forName: "svr2handshakestart.data"),
            Date(timeIntervalSince1970: 1_676_529_724)
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
            return try Svr2Client.create_NOT_FOR_PRODUCTION(mrenclave: mrenclave, attestationMessage: attestationMessage, currentDate: currentDate)
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

    func testSvr2PinHash() {
        for (serviceType, mrenclave, attestationMsg, currentDate) in testCases {
            guard serviceType == ServiceType.svr2 else { continue }

            let pin = Array("password".utf8)
            let username = Array("username".utf8)

            // echo "d6159ba30f90b6eb6ccf1ec844427f052baaf0705da849767471744cdb3f8a5e" | xxd -r -p | base64
            let knownSalt = Data(base64Encoded: "1hWbow+Qtutszx7IREJ/BSuq8HBdqEl2dHF0TNs/il4=")!

            let client = try! Svr2Client.create_NOT_FOR_PRODUCTION(mrenclave: mrenclave, attestationMessage: attestationMsg, currentDate: currentDate)
            let pinHash = try! client.hashPin(pin, forUser: username)

            let expectedHash = try! PinHash(pin: pin, salt: knownSalt)

            XCTAssertEqual(pinHash.encryptionKey, expectedHash.encryptionKey)
            XCTAssertEqual(pinHash.accessKey, expectedHash.accessKey)

        }

    }
}
