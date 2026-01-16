//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import LibSignalClient
import XCTest

#if !os(iOS) || targetEnvironment(simulator)

class SgxTests: TestCaseBase {
    enum ServiceType {
        case svr2, cds2
    }

    let testCases = [
        (
            ServiceType.cds2,
            [UInt8](fromHexString: "39d78f17f8aa9a8e9cdaf16595947a057bac21f014d1abfd6a99b2dfd4e18d1d")!,
            readResource(forName: "cds2handshakestart.data"),
            Date(timeIntervalSince1970: 1_655_857_680)
        ),
        (
            ServiceType.svr2,
            [UInt8](fromHexString: "97f151f6ed078edbbfd72fa9cae694dcc08353f1f5e8d9ccd79a971b10ffc535")!,
            readResource(forName: "svr2handshakestart.data"),
            Date(timeIntervalSince1970: 1_768_516_141)
        ),
    ]

    static func build(
        serviceType: ServiceType,
        mrenclave: [UInt8],
        attestationMessage: Data,
        currentDate: Date
    ) throws -> SgxClient {
        switch serviceType {
        case .cds2:
            return try Cds2Client(
                mrenclave: mrenclave,
                attestationMessage: attestationMessage,
                currentDate: currentDate
            )
        case .svr2:
            return try Svr2Client(
                mrenclave: mrenclave,
                attestationMessage: attestationMessage,
                currentDate: currentDate
            )
        }
    }

    func testCreateClient() {
        for (serviceType, mrenclave, attestationMessage, currentDate) in self.testCases {
            let client = try! SgxTests.build(
                serviceType: serviceType,
                mrenclave: mrenclave,
                attestationMessage: attestationMessage,
                currentDate: currentDate
            )
            let initialMessage = client.initialRequest()
            XCTAssertEqual(1632, initialMessage.count, String(describing: serviceType))
        }
    }

    func testCreateClientFailsWithInvalidMrenclave() {
        let invalidMrenclave = [UInt8]()
        for (serviceType, _, attestationMessage, currentDate) in self.testCases {
            XCTAssertThrowsError(
                try SgxTests.build(
                    serviceType: serviceType,
                    mrenclave: invalidMrenclave,
                    attestationMessage: attestationMessage,
                    currentDate: currentDate
                ),
                String(describing: serviceType)
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
                ),
                String(describing: serviceType)
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

#endif
