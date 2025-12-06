//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

#if canImport(Security)
import Security
#endif

internal func invokeFnReturningValueByPointer<Value>(
    _ initial: Value,
    fn: (UnsafeMutablePointer<Value>?) -> SignalFfiErrorRef?
) throws -> Value {
    var output = initial
    try checkError(fn(&output))
    return output
}

internal func invokeFnReturningString(
    fn: (UnsafeMutablePointer<UnsafePointer<CChar>?>?) -> SignalFfiErrorRef?
) throws -> String {
    try invokeFnReturningOptionalString(fn: fn)!
}

internal func invokeFnReturningOptionalString(
    fn: (UnsafeMutablePointer<UnsafePointer<CChar>?>?) -> SignalFfiErrorRef?
) throws -> String? {
    guard let output = try invokeFnReturningValueByPointer(nil, fn: fn) else {
        return nil
    }
    let result = String(cString: output)
    signal_free_string(output)
    return result
}

internal func invokeFnReturningSomeBytestringArray<Element>(
    fn: (UnsafeMutablePointer<SignalBytestringArray>?) -> SignalFfiErrorRef?,
    transform: (UnsafeBufferPointer<UInt8>) -> Element
) throws -> [Element] {
    let array = try invokeFnReturningValueByPointer(.init(), fn: fn)

    var bytes = UnsafeBufferPointer(start: array.bytes.base, count: array.bytes.length)[...]
    let lengths = UnsafeBufferPointer(start: array.lengths.base, count: array.lengths.length)

    let result = lengths.map { length in
        let view = UnsafeBufferPointer(rebasing: bytes.prefix(length))
        bytes = bytes.dropFirst(length)
        return transform(view)
    }

    signal_free_bytestring_array(array)
    return result
}

internal func invokeFnReturningStringArray(
    fn: (UnsafeMutablePointer<SignalStringArray>?) -> SignalFfiErrorRef?
) throws -> [String] {
    return try invokeFnReturningSomeBytestringArray(fn: fn) {
        String(decoding: $0, as: Unicode.UTF8.self)
    }
}

internal func invokeFnReturningBytestringArray(
    fn: (UnsafeMutablePointer<SignalBytestringArray>?) -> SignalFfiErrorRef?
) throws -> [Data] {
    return try invokeFnReturningSomeBytestringArray(fn: fn) {
        Data($0)
    }
}

internal func invokeFnReturningOptionalArray(
    fn: (UnsafeMutablePointer<SignalOwnedBuffer>?) -> SignalFfiErrorRef?
) throws -> Data? {
    let output = try invokeFnReturningValueByPointer(.init(), fn: fn)

    return if output.base == nil {
        nil
    } else {
        Data(consuming: output)
    }
}

internal func invokeFnReturningData(fn: (UnsafeMutablePointer<SignalOwnedBuffer>?) -> SignalFfiErrorRef?) throws -> Data
{
    try invokeFnReturningOptionalArray(fn: fn) ?? Data()
}

internal func invokeFnReturningFixedLengthArray<ResultAsTuple>(
    fn: (UnsafeMutablePointer<ResultAsTuple>) -> SignalFfiErrorRef?
) throws -> Data {
    precondition(MemoryLayout<ResultAsTuple>.alignment == 1, "not a fixed-sized array (tuple) of UInt8")
    var output = Data(count: MemoryLayout<ResultAsTuple>.size)
    try output.withUnsafeMutableBytes { buffer in
        let typedPointer = buffer.baseAddress!.assumingMemoryBound(to: ResultAsTuple.self)
        return try checkError(fn(typedPointer))
    }
    return output
}

internal func invokeFnReturningSerialized<Result: ByteArray, SerializedResult>(
    fn: (UnsafeMutablePointer<SerializedResult>) -> SignalFfiErrorRef?
) throws -> Result {
    let output = try invokeFnReturningFixedLengthArray(fn: fn)
    return try Result(contents: output)
}

internal func invokeFnReturningVariableLengthSerialized<Result: ByteArray>(
    fn: (UnsafeMutablePointer<SignalOwnedBuffer>?) -> SignalFfiErrorRef?
) throws -> Result {
    let output = try invokeFnReturningData(fn: fn)
    return try Result(contents: output)
}

internal func invokeFnReturningOptionalVariableLengthSerialized<Result: ByteArray>(
    fn: (UnsafeMutablePointer<SignalOwnedBuffer>?) -> SignalFfiErrorRef?
) throws -> Result? {
    let output = try invokeFnReturningData(fn: fn)
    if output.isEmpty {
        return nil
    }
    return try Result(contents: output)
}

internal func invokeFnReturningUuid(fn: (UnsafeMutablePointer<uuid_t>?) -> SignalFfiErrorRef?) throws -> UUID {
    var output: uuid_t = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    try checkError(fn(&output))
    return UUID(uuid: output)
}

internal func invokeFnReturningOptionalUuid(
    fn: (UnsafeMutablePointer<SignalOptionalUuid>?) -> SignalFfiErrorRef?
) throws -> UUID? {
    var output: SignalOptionalUuid = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    try checkError(fn(&output))
    let (isPresent, u0, u1, u2, u3, u4, u5, u6, u7, u8, u9, u10, u11, u12, u13, u14, u15) = output
    if isPresent == 0 {
        return nil
    }
    return UUID(uuid: (u0, u1, u2, u3, u4, u5, u6, u7, u8, u9, u10, u11, u12, u13, u14, u15))
}

internal func invokeFnReturningServiceId<Id: ServiceId>(
    fn: (UnsafeMutablePointer<ServiceIdStorage>?) -> SignalFfiErrorRef?
) throws -> Id {
    var output: ServiceIdStorage = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    try checkError(fn(&output))
    return try Id.parseFrom(fixedWidthBinary: output)
}

internal func invokeFnReturningInteger<Result: FixedWidthInteger>(
    fn: (UnsafeMutablePointer<Result>?) -> SignalFfiErrorRef?
) throws -> Result {
    return try invokeFnReturningValueByPointer(0, fn: fn)
}

internal func invokeFnReturningBool(fn: (UnsafeMutablePointer<Bool>?) -> SignalFfiErrorRef?) throws -> Bool {
    return try invokeFnReturningValueByPointer(false, fn: fn)
}

internal func invokeFnReturningNativeHandle<Owner: NativeHandleOwner<PointerType>, PointerType>(
    fn: (UnsafeMutablePointer<PointerType>?) -> SignalFfiErrorRef?
) throws -> Owner {
    let handle = try invokeFnReturningValueByPointer(PointerType(untyped: nil), fn: fn)
    return Owner(owned: NonNull(handle)!)
}

internal func invokeFnReturningOptionalNativeHandle<Owner: NativeHandleOwner<PointerType>, PointerType>(
    fn: (UnsafeMutablePointer<PointerType>?) -> SignalFfiErrorRef?
) throws -> Owner? {
    let handle = try invokeFnReturningValueByPointer(PointerType(untyped: nil), fn: fn)
    return NonNull<PointerType>(handle).map { Owner(owned: $0) }
}

extension ContiguousBytes {
    func withUnsafeBorrowedBuffer<Result>(_ body: (SignalBorrowedBuffer) throws -> Result) rethrows -> Result {
        try withUnsafeBytes {
            try body(SignalBorrowedBuffer($0))
        }
    }
}

internal func withUnsafeOptionalBorrowedSlice<
    T: ContiguousBytes,
    R
>(
    of this: T?,
    _ body: (SignalOptionalBorrowedSliceOfc_uchar) throws -> R
) rethrows -> R {
    switch this {
    case .none:
        let empty = SignalOptionalBorrowedSliceOfc_uchar()
        return try body(empty)
    case .some(let wrapped):
        return try wrapped.withUnsafeBorrowedBuffer { buffer in
            let slice = SignalOptionalBorrowedSliceOfc_uchar(present: true, value: buffer)
            return try body(slice)
        }
    }
}

extension Sequence where Self.Element == String {
    func withUnsafeBorrowedBytestringArray<Result>(
        _ body: (SignalBorrowedBytestringArray) throws -> Result
    ) rethrows -> Result {
        let lengths = self.map { $0.utf8.count }
        var concatenated = Data(capacity: lengths.reduce(0) { $0 + $1 })
        for s in self {
            concatenated.append(contentsOf: s.utf8)
        }

        return try concatenated.withUnsafeBorrowedBuffer { bytes in
            try lengths.withUnsafeBufferPointer { lengths in
                try body(
                    SignalBorrowedBytestringArray(
                        bytes: bytes,
                        lengths: SignalBorrowedSliceOfusize(base: lengths.baseAddress, length: lengths.count)
                    )
                )
            }
        }
    }
}

extension SignalBorrowedBuffer {
    internal init(_ buffer: UnsafeRawBufferPointer) {
        self.init(base: buffer.baseAddress?.assumingMemoryBound(to: UInt8.self), length: buffer.count)
    }
}

extension SignalBorrowedMutableBuffer {
    internal init(_ buffer: UnsafeMutableRawBufferPointer) {
        self.init(base: buffer.baseAddress?.assumingMemoryBound(to: UInt8.self), length: buffer.count)
    }
}

extension Data {
    internal init(consuming buffer: SignalOwnedBuffer) {
        if let base = buffer.base {
            self.init(
                bytesNoCopy: base,
                count: buffer.length,
                deallocator: .custom { base, length in
                    signal_free_buffer(base, length)
                }
            )
        } else {
            self.init()
        }
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

/// Wraps a store while providing a place to hang on to any user-thrown errors.
internal struct ErrorHandlingContext<Store> {
    var store: Store
    var error: Error? = nil

    init(_ store: Store) {
        self.store = store
    }

    mutating func catchCallbackErrors(_ body: (Store) throws -> Int32) -> Int32 {
        do {
            return try body(self.store)
        } catch {
            self.error = error
            return -1
        }
    }
}

internal func rethrowCallbackErrors<Store, Result>(
    _ store: Store,
    _ body: (UnsafeMutablePointer<ErrorHandlingContext<Store>>) throws -> Result
) rethrows -> Result {
    var context = ErrorHandlingContext(store)
    do {
        return try withUnsafeMutablePointer(to: &context) {
            try body($0)
        }
    } catch SignalError.callbackError(_) where context.error != nil {
        throw context.error!
    }
}

extension Collection {
    public func split(at index: Self.Index) -> (Self.SubSequence, Self.SubSequence) {
        (self.prefix(upTo: index), self.suffix(from: index))
    }
}

extension Optional where Wrapped: StringProtocol {
    internal func withCString<Result>(_ body: (UnsafePointer<CChar>?) throws -> Result) rethrows -> Result {
        guard let wrapped = self else {
            return try body(nil)
        }
        return try wrapped.withCString(body)
    }
}

extension Array where Element == UInt8 {
    /// Converts these bytes to (lowercase) hexadecimal.
    public func toHex() -> String {
        var hex = [UInt8](repeating: 0, count: self.count * 2)
        hex.withUnsafeMutableBytes { hex in
            self.withUnsafeBorrowedBuffer { input in
                failOnError(
                    signal_hex_encode(
                        SignalBorrowedMutableBuffer(hex),
                        input
                    )
                )
            }
        }
        return String(decoding: hex, as: Unicode.UTF8.self)
    }
}

extension Data {
    /// Converts these bytes to (lowercase) hexadecimal.
    public func toHex() -> String {
        var hex = [UInt8](repeating: 0, count: self.count * 2)
        hex.withUnsafeMutableBytes { hex in
            self.withUnsafeBorrowedBuffer { input in
                failOnError(
                    signal_hex_encode(
                        SignalBorrowedMutableBuffer(hex),
                        input
                    )
                )
            }
        }
        return String(decoding: hex, as: Unicode.UTF8.self)
    }
}

extension [String: String] {
    internal func withBridgedStringMap<Result>(
        _ callback: (SignalMutPointerBridgedStringMap) throws -> Result
    ) rethrows -> Result {
        var map = SignalMutPointerBridgedStringMap()
        failOnError(signal_bridged_string_map_new(&map, UInt32(clamping: self.count)))
        defer { signal_bridged_string_map_destroy(map) }

        for (key, value) in self {
            failOnError(signal_bridged_string_map_insert(map, key, value))
        }

        return try callback(map)
    }
}

extension SignalMutPointerBridgedStringMap: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerBridgedStringMap

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        Self.ConstPointer(raw: self.raw)
    }
}

extension SignalConstPointerBridgedStringMap: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
