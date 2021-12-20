//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

internal func invokeFnReturningString(fn: (UnsafeMutablePointer<UnsafePointer<CChar>?>?) -> SignalFfiErrorRef?) throws -> String {
    try invokeFnReturningOptionalString(fn: fn)!
}

internal func invokeFnReturningOptionalString(fn: (UnsafeMutablePointer<UnsafePointer<CChar>?>?) -> SignalFfiErrorRef?) throws -> String? {
    var output: UnsafePointer<Int8>?
    try checkError(fn(&output))
    if output == nil {
        return nil
    }
    let result = String(cString: output!)
    signal_free_string(output)
    return result
}

internal func invokeFnReturningArray(fn: (UnsafeMutablePointer<UnsafePointer<UInt8>?>?, UnsafeMutablePointer<Int>?) -> SignalFfiErrorRef?) throws -> [UInt8] {
    return try invokeFnReturningOptionalArray(fn: fn)!
}

internal func invokeFnReturningOptionalArray(fn: (UnsafeMutablePointer<UnsafePointer<UInt8>?>?, UnsafeMutablePointer<Int>?) -> SignalFfiErrorRef?) throws -> [UInt8]? {
    var output: UnsafePointer<UInt8>?
    var output_len = 0
    try checkError(fn(&output, &output_len))
    if output == nil {
        return nil
    }
    let result = Array(UnsafeBufferPointer(start: output, count: output_len))
    signal_free_buffer(output, output_len)
    return result
}

internal func invokeFnReturningSerialized<Result: ByteArray, SerializedResult>(fn: (UnsafeMutablePointer<SerializedResult>) -> SignalFfiErrorRef?) throws -> Result {
    precondition(MemoryLayout<SerializedResult>.alignment == 1, "not a fixed-sized array (tuple) of UInt8")
    var output = Array(repeating: 0 as UInt8, count: MemoryLayout<SerializedResult>.size)
    try output.withUnsafeMutableBytes { buffer -> Void in
        let typedPointer = buffer.baseAddress!.assumingMemoryBound(to: SerializedResult.self)
        return try checkError(fn(typedPointer))
    }
    return try Result(contents: output)
}

internal func invokeFnReturningUuid(fn: (UnsafeMutablePointer<uuid_t>?) -> SignalFfiErrorRef?) throws -> UUID {
    var output = UUID_NULL
    try checkError(fn(&output))
    return UUID(uuid: output)
}

internal func invokeFnReturningInteger<Result: FixedWidthInteger>(fn: (UnsafeMutablePointer<Result>?) -> SignalFfiErrorRef?) throws -> Result {
    var output: Result = 0
    try checkError(fn(&output))
    return output
}

internal func invokeFnReturningNativeHandle<Owner: NativeHandleOwner>(fn: (UnsafeMutablePointer<OpaquePointer?>?) -> SignalFfiErrorRef?) throws -> Owner {
    var handle: OpaquePointer?
    try checkError(fn(&handle))
    return Owner(owned: handle!)
}

internal func invokeFnReturningOptionalNativeHandle<Owner: NativeHandleOwner>(fn: (UnsafeMutablePointer<OpaquePointer?>?) -> SignalFfiErrorRef?) throws -> Owner? {
    var handle: OpaquePointer?
    try checkError(fn(&handle))
    return handle.map { Owner(owned: $0) }
}
