//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import XCTest

import LibSignalClient

class ServiceIdTests: TestCaseBase {
    static let TEST_UUID_STRING = "e36fdce7-36da-4c6f-a21b-9afe2b754650"
    static let TEST_UUID = UUID(uuidString: TEST_UUID_STRING)!
    static let TEST_UUID_BYTES: [UInt8] = [
        0xe3, 0x6f, 0xdc, 0xe7, 0x36, 0xda, 0x4c, 0x6f,
        0xa2, 0x1b, 0x9a, 0xfe, 0x2b, 0x75, 0x46, 0x50
    ]

    func testAciProperties() throws {
        let aci = Aci(fromUUID: Self.TEST_UUID)
        XCTAssertEqual(.aci, aci.kind)
        XCTAssertEqual(Self.TEST_UUID, aci.rawUUID)
        XCTAssertEqual(Self.TEST_UUID_STRING, aci.serviceIdString)
        XCTAssertEqual(Self.TEST_UUID_STRING.uppercased(), aci.serviceIdUppercaseString)
        XCTAssertEqual(Self.TEST_UUID_BYTES, aci.serviceIdBinary)
        XCTAssertEqual("<ACI:\(Self.TEST_UUID_STRING)>", aci.logString)
        XCTAssertEqual("<ACI:\(Self.TEST_UUID_STRING)>", aci.debugDescription)
        XCTAssertEqual("<ACI:\(Self.TEST_UUID_STRING)>", "\(aci)")
    }

    func testPniProperties() throws {
        let pni = Pni(fromUUID: Self.TEST_UUID)
        XCTAssertEqual(.pni, pni.kind)
        XCTAssertEqual(Self.TEST_UUID, pni.rawUUID)
        XCTAssertEqual("PNI:" + Self.TEST_UUID_STRING, pni.serviceIdString)
        XCTAssertEqual("PNI:" + Self.TEST_UUID_STRING.uppercased(), pni.serviceIdUppercaseString)
        XCTAssertEqual([1] + Self.TEST_UUID_BYTES, pni.serviceIdBinary)
        XCTAssertEqual("<PNI:\(Self.TEST_UUID_STRING)>", pni.logString)
        XCTAssertEqual("<PNI:\(Self.TEST_UUID_STRING)>", pni.debugDescription)
        XCTAssertEqual("<PNI:\(Self.TEST_UUID_STRING)>", "\(pni)")
    }

    // swiftlint:disable force_cast
    func testParseFromString() throws {
        _ = try! ServiceId.parseFrom(
            serviceIdString: Self.TEST_UUID_STRING) as! Aci
        _ = try! ServiceId.parseFrom(
            serviceIdString: "PNI:" + Self.TEST_UUID_STRING) as! Pni
        do {
            _ = try ServiceId.parseFrom(serviceIdString: "ACI:" + Self.TEST_UUID_STRING)
            XCTFail("Should have failed")
        } catch SignalError.invalidArgument { }
        do {
            _ = try ServiceId.parseFrom(serviceIdString: "")
            XCTFail("Should have failed")
        } catch SignalError.invalidArgument { }
    }

    func testParseFromBinary() throws {
        _ = try! ServiceId.parseFrom(
            serviceIdBinary: Aci(fromUUID: UUID()).serviceIdBinary) as! Aci
        _ = try! ServiceId.parseFrom(
            serviceIdBinary: Pni(fromUUID: UUID()).serviceIdBinary) as! Pni
        do {
            _ = try ServiceId.parseFrom(serviceIdBinary: [0] + Self.TEST_UUID_BYTES)
            XCTFail("Should have failed")
        } catch SignalError.invalidArgument { }
        do {
            _ = try ServiceId.parseFrom(serviceIdBinary: [])
            XCTFail("Should have failed")
        } catch SignalError.invalidArgument { }
    }
    // swiftlint:enable force_cast
}
