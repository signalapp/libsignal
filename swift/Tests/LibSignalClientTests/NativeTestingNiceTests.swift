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

struct NativeTestingNiceTests {
    private func testConversion<Item: Equatable>(
        items: any Sequence<Item>,
        toString: (Item) throws -> String,
        nativeToString: (Item) throws -> String,
        nativeIdentity: (Item) throws -> Item,
    ) throws {
        for item in items {
            let swiftString = try toString(item)
            let nativeString = try nativeToString(item)
            #expect(swiftString == nativeString)
            let actualIdentity = try nativeIdentity(item)
            #expect(item == actualIdentity)
        }
    }
    @Test
    func testString() throws {
        try testConversion(
            items: ["", "abc", "îüéè"],
            toString: { $0 },
            nativeToString: {
                try NativeTestingNice.TESTING_conversion_string_identity(x: $0)
            },
            nativeIdentity: {
                try NativeTestingNice.TESTING_conversion_string_identity(x: $0)
            },
        )
    }
    @Test
    func testBool() throws {
        try testConversion(
            items: [true, false],
            toString: { "\($0)" },
            nativeToString: { try NativeTestingNice.TESTING_conversion_bool_to_string(x: $0) },
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_bool_identity(x: $0) }
        )
    }
    @Test
    func testU8() throws {
        try testConversion(
            items: UInt8.min...UInt8.max,
            toString: { "\($0)" },
            nativeToString: { try NativeTestingNice.TESTING_conversion_u8_to_string(x: $0) },
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_u8_identity(x: $0) }
        )
    }
    @Test
    func testU16() throws {
        try testConversion(
            items: UInt16.min...UInt16.max,
            toString: { "\($0)" },
            nativeToString: { try NativeTestingNice.TESTING_conversion_u16_to_string(x: $0) },
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_u16_identity(x: $0) }
        )
    }
    @Test
    func testI32() throws {
        try testConversion(
            items: -1024...1024,
            toString: { "\($0)" },
            nativeToString: { try NativeTestingNice.TESTING_conversion_i32_to_string(x: $0) },
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_i32_identity(x: $0) }
        )
    }
    @Test
    func testServiceId() throws {
        try testConversion(
            items: [
                Aci(fromUUID: UUID()),
                Pni(fromUUID: UUID()),
                Aci(fromUUID: UUID()),
                Pni(fromUUID: UUID()),
            ],
            toString: { $0.serviceIdString },
            nativeToString: { try NativeTestingNice.TESTING_conversion_ServiceId_to_string(x: $0) },
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_ServiceId_identity(x: $0) }
        )
    }
    @Test
    func testData() throws {
        try testConversion(
            items: (0..<10).lazy.map { count in Data((0..<(1 << count)).map { _ in UInt8.random(in: 0...255) }) },
            toString: { $0.base64EncodedString() },
            nativeToString: { try NativeTestingNice.TESTING_conversion_Data_to_string(x: $0) },
            nativeIdentity: { try NativeTestingNice.TESTING_conversion_Data_identity(x: $0) }
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
}

#endif
