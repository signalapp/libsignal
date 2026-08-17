//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// These testing endpoints aren't generated in device builds, to save on code size.
#if !os(iOS) || targetEnvironment(simulator)

@testable import LibSignalClient
import Foundation
import SignalFfi
import Testing

internal enum MyNiceTypeEnum {
    case unit
    case single(Int32)
}
internal enum MyNiceTypeSimpleEnum {
    case a
    case b
}
internal struct MyNiceTypeStruct {
    var x: Int32
    var y: Int32
}

extension NiceArgConverter {
    fileprivate static func testConversion(
        items: any Sequence<NiceArg>,
        toString: (NiceArg) throws -> String,
        nativeToString: (NiceArg) throws -> String,
        rawNativeToString: (UnsafeMutablePointer<UnsafePointer<CChar>?>?, FfiArg) -> SignalFfiErrorRef?,
        nativeIdentity: (NiceArg) throws -> NiceArg,
    ) throws {
        for item in items {
            let swiftString = try toString(item)
            let nativeString = try nativeToString(item)
            #expect(swiftString == nativeString)
            let actualIdentity = try nativeIdentity(item)
            let actualIdentityString = try toString(actualIdentity)
            #expect(actualIdentityString == nativeString)
            // Manually check both the borrowed and keep alive forms
            let rawBorrowedNativeString = try self.convertArgBorrowed(item) { itemFfi in
                var rawOutput = StringConverter.emptyFfiReturn()
                try checkError(
                    rawNativeToString(
                        &rawOutput,
                        itemFfi,
                    )
                )
                return try StringConverter.convertReturn(consuming: rawOutput)
            }
            #expect(swiftString == rawBorrowedNativeString)
            let rawKeepAliveNativeString = try self.genericArgBorrowed(item) { itemFfi in
                var rawOutput = StringConverter.emptyFfiReturn()
                try checkError(
                    rawNativeToString(
                        &rawOutput,
                        itemFfi,
                    )
                )
                return try StringConverter.convertReturn(consuming: rawOutput)
            }
            #expect(swiftString == rawKeepAliveNativeString)
        }
    }
}

struct NativeTestingNiceTests {
    @Test
    func testString() throws {
        try StringConverter.testConversion(
            items: ["", "abc", "îüéè"],
            toString: { $0 },
            nativeToString: {
                try NativeTestingNice.TESTING_conversion_string_identity(x: $0)
            },
            rawNativeToString: SignalFfi.signal_testing_conversion_string_identity,
            nativeIdentity: {
                try NativeTestingNice.TESTING_conversion_string_identity(x: $0)
            },
        )
    }
    @Test
    func testBool() throws {
        try IdentityConverter<Bool>.testConversion(
            items: [true, false],
            toString: { "\($0)" },
            nativeToString: { try NativeTestingNice.TESTING_conversion_bool_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_conversion_bool_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_bool_identity(x: $0) }
        )
    }
    @Test
    func testU8() throws {
        try IdentityConverter<UInt8>.testConversion(
            items: UInt8.min...UInt8.max,
            toString: { "\($0)" },
            nativeToString: { try NativeTestingNice.TESTING_conversion_u8_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_conversion_u8_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_u8_identity(x: $0) }
        )
    }
    @Test
    func testU16() throws {
        try IdentityConverter<UInt16>.testConversion(
            items: UInt16.min...UInt16.max,
            toString: { "\($0)" },
            nativeToString: { try NativeTestingNice.TESTING_conversion_u16_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_conversion_u16_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_u16_identity(x: $0) }
        )
    }
    @Test
    func testI32() throws {
        try IdentityConverter<Int32>.testConversion(
            items: -1024...1024,
            toString: { "\($0)" },
            nativeToString: { try NativeTestingNice.TESTING_conversion_i32_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_conversion_i32_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_i32_identity(x: $0) }
        )
    }
    @Test
    func testServiceId() throws {
        try ServiceIdConverter.testConversion(
            items: [
                Aci(fromUUID: UUID()),
                Pni(fromUUID: UUID()),
                Aci(fromUUID: UUID()),
                Pni(fromUUID: UUID()),
            ],
            toString: { $0.serviceIdString },
            nativeToString: { try NativeTestingNice.TESTING_conversion_ServiceId_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_conversion_service_id_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_ServiceId_identity(x: $0) }
        )
    }
    @Test
    func testData() throws {
        try DataConverter.testConversion(
            items: (0..<10).lazy.map { count in Data((0..<(1 << count)).map { _ in UInt8.random(in: 0...255) }) },
            toString: { $0.base64EncodedString() },
            nativeToString: { try NativeTestingNice.TESTING_conversion_Data_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_conversion_data_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_Data_identity(x: $0) }
        )
    }
    @Test
    func testOptionalBytes() throws {
        try OptionalArgConverter<DataConverter, SignalOptionalOfBorrowedBuffer>.testConversion(
            items: [nil, Data(), Data([0]), Data([0, 1])],
            toString: { $0?.base64EncodedString() ?? "%" },
            nativeToString: { try NativeTestingNice.TESTING_conversion_OptionalBytes_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_conversion_optional_bytes_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_OptionalBytes_identity(x: $0) },
        )
    }
    @Test
    func testOptionalString() throws {
        try OptionalStringConverter.testConversion(
            items: [nil, "", "a", "abc"],
            toString: {
                if let x = $0 {
                    "\"\(x)\""
                } else {
                    "null"
                }
            },
            nativeToString: { try NativeTestingNice.TESTING_conversion_OptionalString_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_conversion_optional_string_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_OptionalString_identity(x: $0) },
        )
    }
    @Test
    func testData32() throws {
        try FixedByteArrayConverter<FixedByteArrayHelper32>.testConversion(
            items: [Data((0..<32).map { _ in UInt8.random(in: 0...255) })],
            toString: { $0.base64EncodedString() },
            nativeToString: { try NativeTestingNice.TESTING_conversion_Data32_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_conversion_data32_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_Data32_identity(x: $0) }
        )
    }
    @Test
    func testBridgeVecData32() throws {
        try ArrayArgConverter<
            FixedByteArrayConverter<FixedByteArrayHelper32>,
            SignalBorrowedSliceOfc_uchar32
        >.testConversion(
            items: (0..<8).map { count in
                (0..<count).map { _ in Data((0..<32).map { _ in UInt8.random(in: 0...255) }) }
            },
            toString: { $0.map { $0.base64EncodedString() }.joined(separator: "\n") },
            nativeToString: { try NativeTestingNice.TESTING_conversion_BridgeVecData32_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_conversion_bridge_vec_data32_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_BridgeVecData32_identity(x: $0) }
        )
    }
    @Test
    func testDeviceId() throws {
        try DeviceIdConverter.testConversion(
            items: (1...127).map { DeviceId(validating: $0)! },
            toString: { $0.description },
            nativeToString: { try NativeTestingNice.TESTING_conversion_DeviceId_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_conversion_device_id_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_DeviceId_identity(x: $0) },
        )
    }
    @Test
    func testMyTestSimpleEnum() throws {
        try DerivedArgConverterMySimpleTestEnum.testConversion(
            items: [.a, .b],
            toString: {
                switch $0 {
                case .a: "A"
                case .b: "B"
                }
            },
            nativeToString: { try NativeTestingNice.TESTING_MySimpleTestEnum_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_my_simple_test_enum_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_MySimpleTestEnum_identity(x: $0) },
        )
    }
    @Test
    func testMySimpleTestEnumBridgeVec() throws {
        try ArrayArgConverter<
            DerivedArgConverterMySimpleTestEnum,
            SignalFfi.SignalBorrowedSliceOfMySimpleTestEnumFfiArg,
        >
        .testConversion(
            items: [[], [.a], [.b], [.a, .b], [.a, .a, .b], [.b, .b]],
            toString: {
                String(
                    bytes: try JSONEncoder().encode(
                        $0.map {
                            switch $0 {
                            case .a: "A"
                            case .b: "B"
                            }
                        }
                    ),
                    encoding: .utf8
                )!
            },
            nativeToString: { try NativeTestingNice.TESTING_MySimpleTestEnum_BridgeVec_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_my_simple_test_enum_bridge_vec_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_MySimpleTestEnum_BridgeVec_identity(x: $0) }
        )
    }
    @Test
    func testDataVecU8() throws {
        try DataConverter.testConversion(
            items: (0..<10).lazy.map { count in Data((0..<(1 << count)).map { _ in UInt8.random(in: 0...255) }) },
            toString: { $0.base64EncodedString() },
            nativeToString: { try NativeTestingNice.TESTING_conversion_Data_VecU8_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_conversion_data_vec_u8_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_Data_VecU8_identity(x: $0) }
        )
    }
    @Test
    func testBridgeVecString() throws {
        try ArrayArgConverter<
            StringConverter, SignalBorrowedSliceOfCStringPtr
        >
        .testConversion(
            items: [[], ["one"], ["one", "two"], ["one", "two", "three"]],
            toString: { String(bytes: try JSONEncoder().encode($0), encoding: .utf8)! },
            nativeToString: { try NativeTestingNice.TESTING_conversion_BridgeVecString_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_conversion_bridge_vec_string_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_BridgeVecString_identity(x: $0) },
        )
    }
    @Test
    func testMyTestPoint() throws {
        try DerivedArgConverterMyTestPoint.testConversion(
            items: [MyTestPoint(1, 2)],
            toString: { "[\($0._0),\($0._1)]" },
            nativeToString: { try NativeTestingNice.TESTING_MyTestPoint_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_my_test_point_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_MyTestPoint_identity(x: $0) },
        )
    }
    @Test
    func testMyTestStruct() throws {
        try DerivedArgConverterMyTestStruct.testConversion(
            items: [MyTestStruct(myNumericField: 123, myStringField: "string!")],
            toString: { "{\"myNumericField\":\($0.myNumericField),\"myStringField\":\"\($0.myStringField)\"}" },
            nativeToString: { try NativeTestingNice.TESTING_MyTestStruct_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_my_test_struct_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_MyTestStruct_identity(x: $0) },
        )
    }
    @Test
    func testMyTestEnum() throws {
        try DerivedArgConverterMyTestEnum.testConversion(
            items: [
                .unit,
                .single(73),
                .record(
                    personName: "Person!",
                    personAge: 101,
                    position: MyTestPoint(3, 4),
                    funStruct: MyTestStruct(myNumericField: 847, myStringField: "string!")
                ),
                .singleNamed(x: 847),
                .double(8, 9),
            ],
            toString: { value in
                return switch value {
                case .double(let x, let y): #"{"double":[\#(x),\#(y)]}"#
                case .record(let personName, let personAge, let position, let funStruct):
                    #"{"record":{"personName":"\#(personName)","personAge":\#(personAge),"#
                        + #""position":[\#(position._0),\#(position._1)],"#
                        + #""funStruct":{"myNumericField":\#(funStruct.myNumericField),"#
                        + #""myStringField":"\#(funStruct.myStringField)"}}}"#
                case .single(let x): #"{"single":\#(x)}"#
                case .singleNamed(let x): #"{"singleNamed":{"x":\#(x)}}"#
                case .unit: #""unit""#
                }
            },
            nativeToString: { try NativeTestingNice.TESTING_MyTestEnum_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_my_test_enum_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_MyTestEnum_identity(x: $0) },
        )
    }

    @Test
    func testTimestamp() throws {
        try TimestampConverter.testConversion(
            items: [Date(timeIntervalSince1970: 0), Date(timeIntervalSince1970: 1782938926.226)],
            toString: { date in
                let ms = UInt64(date.timeIntervalSince1970 * 1000.0)
                let stamp = Date.ISO8601FormatStyle(
                    dateSeparator: .dash,
                    dateTimeSeparator: .standard,
                    timeSeparator: .colon,
                    timeZoneSeparator: .colon,
                    includingFractionalSeconds: true,
                ).format(date)
                return "\(ms)ms \(stamp)"
            },
            nativeToString: { try NativeTestingNice.TESTING_conversion_Timestamp_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_conversion_timestamp_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_Timestamp_identity(x: $0) },
        )
    }

    let testFloats = [
        0.0,
        1.2,
        -1.2,
        Float.nan,
        Float.infinity,
        -Float.infinity,
    ]

    func float2str(_ x: Float) -> String {
        if x == 0.0 {
            "0"
        } else if x.isNaN {
            "NaN"
        } else {
            "\(x)"
        }
    }

    @Test
    func testFloat() throws {
        try IdentityConverter<Float>
            .testConversion(
                items: testFloats,
                toString: float2str,
                nativeToString: { try NativeTestingNice.TESTING_conversion_Float_to_string(x: $0) },
                rawNativeToString: SignalFfi.signal_testing_conversion_float_to_string,
                nativeIdentity: { try NativeTestingNice.TESTING_conversion_Float_identity(x: $0) },
            )
    }

    @Test
    func testOptionalFloat() throws {
        try OptionalArgConverter<IdentityConverter<Float>, SignalOptionalOff32>
            .testConversion(
                items: testFloats + [nil],
                toString: {
                    if let x = $0 {
                        float2str(x)
                    } else {
                        ""
                    }
                },
                nativeToString: { try NativeTestingNice.TESTING_conversion_OptionalFloat_to_string(x: $0) },
                rawNativeToString: SignalFfi.signal_testing_conversion_optional_float_to_string,
                nativeIdentity: { try NativeTestingNice.TESTING_conversion_OptionalFloat_identity(x: $0) },
            )
    }

    @Test
    func testMyNiceTypeSimpleEnum() throws {
        try DerivedArgConverterMyNiceTypeSimpleEnumNot.testConversion(
            items: [.a, .b],
            toString: {
                switch $0 {
                case .a:
                    "\"A\""
                case .b:
                    "\"B\""
                }
            },
            nativeToString: { try NativeTestingNice.TESTING_MyNiceTypeSimpleEnum_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_my_nice_type_simple_enum_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_MyNiceTypeSimpleEnum_identity(x: $0) }
        )
    }

    @Test
    func testMyNiceTypeEnum() throws {
        try DerivedArgConverterMyNiceTypeEnumNot.testConversion(
            items: [.unit, .single(12)],
            toString: {
                switch $0 {
                case .single(let x):
                    "{\"Single\":\(x)}"
                case .unit:
                    "\"Unit\""
                }
            },
            nativeToString: { try NativeTestingNice.TESTING_MyNiceTypeEnum_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_my_nice_type_enum_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_MyNiceTypeEnum_identity(x: $0) }
        )
    }

    @Test
    func testMyNiceTypeStruct() throws {
        try DerivedArgConverterMyNiceTypeStructNot.testConversion(
            items: [.init(x: 1, y: 2)],
            toString: {
                "{\"x\":\($0.x),\"y\":\($0.y)}"
            },
            nativeToString: { try NativeTestingNice.TESTING_MyNiceTypeStruct_to_string(x: $0) },
            rawNativeToString: SignalFfi.signal_testing_my_nice_type_struct_to_string,
            nativeIdentity: { try NativeTestingNice.TESTING_MyNiceTypeStruct_identity(x: $0) }
        )
    }

    @Test
    func asyncTest() async throws {
        let ctx = TokioAsyncContext()
        for c in [0, 1, 2, 4, 8, 16, 32, 64, 128, 256] {
            let out = try await NativeTestingNice.TESTING_TokioAsyncContext_FutureSuccessBytes(
                asyncContext: ctx,
                count: Int32(c),
            )
            #expect(out.count == c)
        }
    }

    @Test
    func testReturnedError() {
        switch try! NativeTestingNice.TESTING_ReturnIoError() {
        case SignalError.ioError("IO error: testing"): break
        case let other: Issue.record("wrong error: \(other)")
        }

        switch try! NativeTestingNice.TESTING_ReturnSomeIoError(present: true) {
        case SignalError.ioError("IO error: testing")?: break
        case let other?: Issue.record("wrong error: \(other)")
        case nil: Issue.record("missing error")
        }

        switch try! NativeTestingNice.TESTING_ReturnSomeIoError(present: false) {
        case let error?: Issue.record("unexpected error: \(error)")
        case nil: break
        }
    }
}

#endif
