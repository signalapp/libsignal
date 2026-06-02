//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

// WARNING: this file was automatically generated

#if !os(iOS) || targetEnvironment(simulator)

import Foundation
import SignalFfi
@testable import LibSignalClient

internal enum NativeTestingNice {
    internal static func TESTING_TestingIntBox_Get(
        myIntBox my_int_box: TestingIntBox,
    ) throws -> Int32 {
        try BridgeHandleRefConverter<SignalMutPointerTestingIntBox, TestingIntBox>.convertArgBorrowed(my_int_box) {
            my_int_boxFfi in
            var rawOutput = IdentityConverter<Int32>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_testing_int_box_get(
                    &rawOutput,
                    my_int_boxFfi,
                )
            )
            return try IdentityConverter<Int32>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_TokioAsyncContext_FutureSuccessBytes(
        asyncContext: TokioAsyncContext,
        count: Int32,
    ) async throws -> Data {
        let rawOutput: DataConverter.FfiReturn =
            try await asyncContext.invokeAsyncFunction {
                promiseFfi,
                asyncContextFfi in
                IdentityConverter<Int32>.convertArgBorrowed(count) { countFfi in
                    SignalFfi.signal_testing_tokio_async_context_future_success_bytes(
                        promiseFfi,
                        asyncContextFfi.const(),
                        countFfi,
                    )
                }
            }
        return try DataConverter.convertReturn(consuming: rawOutput)

    }
    internal static func TESTING_conversion_Data_identity(
        x: Data,
    ) throws -> Data {
        try DataConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = DataConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_data_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try DataConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_Data_to_string(
        x: Data,
    ) throws -> String {
        try DataConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_data_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_ServiceId_identity(
        x: ServiceId,
    ) throws -> ServiceId {
        try ServiceIdConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = ServiceIdConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_service_id_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try ServiceIdConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_ServiceId_to_string(
        x: ServiceId,
    ) throws -> String {
        try ServiceIdConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_service_id_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_bool_identity(
        x: Bool,
    ) throws -> Bool {
        try IdentityConverter<Bool>.convertArgBorrowed(x) { xFfi in
            var rawOutput = IdentityConverter<Bool>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_bool_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try IdentityConverter<Bool>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_bool_to_string(
        x: Bool,
    ) throws -> String {
        try IdentityConverter<Bool>.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_bool_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_i32_identity(
        x: Int32,
    ) throws -> Int32 {
        try IdentityConverter<Int32>.convertArgBorrowed(x) { xFfi in
            var rawOutput = IdentityConverter<Int32>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_i32_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try IdentityConverter<Int32>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_i32_to_string(
        x: Int32,
    ) throws -> String {
        try IdentityConverter<Int32>.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_i32_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_string_identity(
        x: String,
    ) throws -> String {
        try StringConverter.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_string_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_u16_identity(
        x: UInt16,
    ) throws -> UInt16 {
        try IdentityConverter<UInt16>.convertArgBorrowed(x) { xFfi in
            var rawOutput = IdentityConverter<UInt16>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_u16_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try IdentityConverter<UInt16>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_u16_to_string(
        x: UInt16,
    ) throws -> String {
        try IdentityConverter<UInt16>.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_u16_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_u8_identity(
        x: UInt8,
    ) throws -> UInt8 {
        try IdentityConverter<UInt8>.convertArgBorrowed(x) { xFfi in
            var rawOutput = IdentityConverter<UInt8>.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_u8_identity(
                    &rawOutput,
                    xFfi,
                )
            )
            return try IdentityConverter<UInt8>.convertReturn(consuming: rawOutput)
        }

    }
    internal static func TESTING_conversion_u8_to_string(
        x: UInt8,
    ) throws -> String {
        try IdentityConverter<UInt8>.convertArgBorrowed(x) { xFfi in
            var rawOutput = StringConverter.emptyFfiReturn()
            try checkError(
                SignalFfi.signal_testing_conversion_u8_to_string(
                    &rawOutput,
                    xFfi,
                )
            )
            return try StringConverter.convertReturn(consuming: rawOutput)
        }

    }
}

#endif
