//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

#if canImport(Security)
import Security
#endif

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

internal func invokeFnReturningVariableLengthSerialized<Result: ByteArray>(fn: (UnsafeMutablePointer<UnsafePointer<UInt8>?>?, UnsafeMutablePointer<Int>?) -> SignalFfiErrorRef?) throws -> Result {
    let output = try invokeFnReturningArray(fn: fn)
    return try Result(contents: output)
}

internal func invokeFnReturningOptionalVariableLengthSerialized<Result: ByteArray>(fn: (UnsafeMutablePointer<UnsafePointer<UInt8>?>?, UnsafeMutablePointer<Int>?) -> SignalFfiErrorRef?) throws -> Result? {
    let output = try invokeFnReturningOptionalArray(fn: fn)
    return try output.map { try Result(contents: $0) }
}

internal func invokeFnReturningUuid(fn: (UnsafeMutablePointer<uuid_t>?) -> SignalFfiErrorRef?) throws -> UUID {
    var output: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
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

extension ContiguousBytes {
    func withUnsafeBorrowedBuffer<Result>(_ body: (SignalBorrowedBuffer) throws -> Result) rethrows -> Result {
        try withUnsafeBytes {
            try body(SignalBorrowedBuffer($0))
        }
    }
}

extension SignalBorrowedBuffer {
    internal init(_ buffer: UnsafeRawBufferPointer) {
        self.init(base: buffer.baseAddress?.assumingMemoryBound(to: UInt8.self), length: UInt(buffer.count))
    }
}

extension SignalBorrowedMutableBuffer {
    internal init(_ buffer: UnsafeMutableRawBufferPointer) {
        self.init(base: buffer.baseAddress?.assumingMemoryBound(to: UInt8.self), length: UInt(buffer.count))
    }
}

internal func fillRandom(_ buffer: UnsafeMutableRawBufferPointer) throws {
    guard let baseAddress = buffer.baseAddress else {
        // Zero-length buffers are permitted to have nil baseAddresses.
        assert(buffer.count == 0)
        return
    }

#if canImport(Security)
    let result = SecRandomCopyBytes(kSecRandomDefault, buffer.count, baseAddress)
    guard result == errSecSuccess else {
      throw SignalError.internalError("SecRandomCopyBytes failed (error code \(result))")
    }
#else
    for i in buffer.indices {
        buffer[i] = UInt8.random(in: .min ... .max)
    }
#endif
}
