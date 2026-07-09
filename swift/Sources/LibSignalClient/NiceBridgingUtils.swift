//
// Copyright 2026 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

internal protocol NiceArgConverter {
    associatedtype NiceArg
    associatedtype FfiArg
    associatedtype KeepAlive

    /// The resulting ``FfiArg`` should be valid so long as ``arg`` _and_ ``KeepAlive`` are kept alive
    ///
    /// Because ``arg`` will be kept alive by default, there's no need to explicitly return it with ``KeepAlive``
    static func convertArg(_ arg: NiceArg) -> (FfiArg, KeepAlive?)

    static func convertArgBorrowed<Result>(_ arg: NiceArg, _ thunk: (FfiArg) throws -> Result) rethrows -> Result
}

extension NiceArgConverter {
    static internal func genericArgBorrowed<Result>(
        _ arg: NiceArg,
        _ thunk: (FfiArg) throws -> Result
    ) rethrows -> Result {
        return try withExtendedLifetime(arg) {
            let (ffi, ka) = convertArg(arg)
            return try withExtendedLifetime(ka) {
                return try thunk(ffi)
            }
        }
    }
}

internal protocol NiceReturnConverter {
    associatedtype NiceReturn
    associatedtype FfiReturn

    static func emptyFfiReturn() -> FfiReturn
    /// ``consuming`` should be fully consumed (and freed if needed) even if this function throws.
    static func convertReturn(consuming value: FfiReturn) throws -> NiceReturn
}

/// This is only used for Promises, which can't actually return `void` in C.
internal struct VoidConverter: NiceReturnConverter {
    typealias NiceReturn = Void
    typealias FfiReturn = Bool

    static func emptyFfiReturn() -> Bool {
        false
    }
    static func convertReturn(consuming value: Bool) throws {
        _ = value
    }
}

internal struct DataConverter: NiceArgConverter, NiceReturnConverter {
    typealias NiceArg = Data
    typealias FfiArg = SignalBorrowedBuffer
    typealias KeepAlive = NSData
    typealias FfiReturn = SignalOwnedBuffer
    typealias NiceReturn = Data

    static func convertReturn(consuming value: FfiReturn) throws -> Data {
        Data(consuming: value)
    }

    static func emptyFfiReturn() -> SignalOwnedBuffer {
        SignalOwnedBuffer()
    }

    static func convertArg(_ arg: Data) -> (SignalBorrowedBuffer, NSData?) {
        let nsdata = arg as NSData
        return (
            SignalBorrowedBuffer(base: nsdata.bytes.assumingMemoryBound(to: UInt8.self), length: nsdata.length),
            nsdata
        )
    }

    static func convertArgBorrowed<Result>(
        _ arg: Data,
        _ thunk: (SignalBorrowedBuffer) throws -> Result
    ) rethrows -> Result {
        return try arg.withBorrowed(thunk)
    }
}

internal struct StringConverter: NiceArgConverter, NiceReturnConverter {
    typealias NiceArg = String
    typealias FfiArg = UnsafePointer<CChar>?
    typealias KeepAlive = NSString
    typealias FfiReturn = UnsafePointer<CChar>?
    typealias NiceReturn = String

    static func convertArg(_ arg: String) -> (UnsafePointer<CChar>?, NSString?) {
        let nsstring = arg as NSString
        return (nsstring.utf8String, nsstring)
    }

    static func convertArgBorrowed<Result>(
        _ arg: String,
        _ thunk: (UnsafePointer<CChar>?) throws -> Result
    ) rethrows -> Result {
        return try arg.withCString(thunk)
    }

    static func emptyFfiReturn() -> UnsafePointer<CChar>? {
        nil
    }

    static func convertReturn(consuming value: FfiReturn) throws -> NiceReturn {
        guard let value = value else {
            throw SignalError.invalidArgument("null CString")
        }
        defer { signal_free_string(value) }
        return String(cString: value)
    }
}

internal protocol DefaultInit {
    init()
}
extension Bool: DefaultInit {}
extension Int64: DefaultInit {}
extension UInt64: DefaultInit {}
extension Int32: DefaultInit {}
extension UInt32: DefaultInit {}
extension Int16: DefaultInit {}
extension UInt16: DefaultInit {}
extension Int8: DefaultInit {}
extension UInt8: DefaultInit {}

internal struct IdentityConverter<T: DefaultInit>: NiceArgConverter, NiceReturnConverter {
    typealias NiceArg = T
    typealias FfiArg = T
    typealias KeepAlive = ()
    typealias NiceReturn = T
    typealias FfiReturn = T

    static func convertArg(_ arg: T) -> (T, ()?) {
        (arg, nil)
    }

    static func convertArgBorrowed<Result>(_ arg: T, _ thunk: (T) throws -> Result) rethrows -> Result {
        return try thunk(arg)
    }

    static func emptyFfiReturn() -> T {
        return T()
    }

    static func convertReturn(consuming value: T) throws -> T {
        return value
    }
}

internal struct ServiceIdConverter: NiceArgConverter, NiceReturnConverter {
    static func emptyFfiReturn() -> ServiceIdStorage {
        return (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    }

    static func convertArgBorrowed<Result>(
        _ arg: ServiceId,
        _ thunk: (UnsafePointer<ServiceIdStorage>) throws -> Result
    ) rethrows -> Result {
        return try arg.withPointerToFixedWidthBinary(thunk)
    }

    static func convertArg(_ arg: ServiceId) -> (UnsafePointer<ServiceIdStorage>, NSData?) {
        let data = arg.serviceIdFixedWidthBinary as NSData
        return (data.bytes.assumingMemoryBound(to: ServiceIdStorage.self), data)
    }

    static func convertReturn(consuming value: ServiceIdStorage) throws -> ServiceId {
        return try ServiceId.parseFrom(fixedWidthBinary: value)
    }

    typealias NiceArg = ServiceId
    typealias FfiArg = UnsafePointer<ServiceIdStorage>
    typealias KeepAlive = NSData
    typealias NiceReturn = ServiceId
    typealias FfiReturn = ServiceIdStorage
}

internal struct BridgeHandleRefConverter<Ptr: SignalMutPointer, T: NativeHandleOwner<Ptr>>: NiceArgConverter {
    typealias NiceArg = T
    typealias FfiArg = Ptr.ConstPointer
    typealias KeepAlive = ()
    static func convertArg(_ arg: NiceArg) -> (FfiArg, KeepAlive?) {
        // Safe because arg will be kept alive by the caller
        return (arg.unsafeNativeHandle.const(), nil)
    }
    static func convertArgBorrowed<Result>(_ arg: NiceArg, _ thunk: (FfiArg) throws -> Result) rethrows -> Result {
        return try arg.withNativeHandle {
            try thunk($0.const())
        }
    }
}

internal struct BridgeHandleConverter<Ptr: SignalMutPointer, T: NativeHandleOwner<Ptr>>: NiceReturnConverter {
    typealias NiceReturn = T
    typealias FfiReturn = Ptr
    static func emptyFfiReturn() -> Ptr {
        Ptr(untyped: nil)
    }
    static func convertReturn(consuming value: Ptr) throws -> T {
        return T(owned: NonNull(value)!)
    }
}

internal struct ByteArrayConverter<T: ByteArray>: NiceArgConverter {
    typealias NiceArg = T
    typealias FfiArg = SignalBorrowedBuffer
    typealias KeepAlive = NSData

    static func convertArg(_ arg: T) -> (FfiArg, KeepAlive?) {
        return DataConverter.convertArg(arg.serialize())
    }
    static func convertArgBorrowed<Result>(
        _ arg: T,
        _ thunk: (SignalBorrowedBuffer) throws -> Result
    ) rethrows -> Result {
        try arg.serialize().withBorrowed(thunk)
    }
}

internal struct ErrorConverter: NiceReturnConverter {
    typealias NiceReturn = Error
    typealias FfiReturn = SignalFfiErrorRef?
    static func emptyFfiReturn() -> SignalFfiErrorRef? {
        nil
    }
    static func convertReturn(consuming value: SignalFfiErrorRef?) throws -> Error {
        convertError(value)!
    }
}

internal struct OptionalErrorConverter: NiceReturnConverter {
    typealias NiceReturn = Error?
    typealias FfiReturn = SignalFfiErrorRef?
    static func emptyFfiReturn() -> SignalFfiErrorRef? {
        nil
    }
    static func convertReturn(consuming value: SignalFfiErrorRef?) throws -> Error? {
        convertError(value)
    }
}

internal struct BulkPolledStreamTerminationConverter: NiceReturnConverter {
    // The real MAP_FAILED constant lives in the C stdlib (Darwin, or Glibc for Linux testing)
    // as a macro, so it's already part of the C library's ABI.
    // But the Swift distribution shadows the macro to make sure it has a consistent type,
    // and a side effect of that means it ends up being an opaque value.
    // By redefining it here, we can inline it into the convert function.
    static let MAP_FAILED_BIT_PATTERN: Int = -1

    typealias NiceReturn = BulkPolledStreamTermination?
    typealias FfiReturn = SignalFfiBulkPolledStreamTerminationReason
    static func emptyFfiReturn() -> SignalFfiBulkPolledStreamTerminationReason {
        .init()
    }
    static func convertReturn(
        consuming value: SignalFfiBulkPolledStreamTerminationReason
    ) throws -> BulkPolledStreamTermination? {
        switch Int(bitPattern: value.raw) {
        case 0: nil
        case MAP_FAILED_BIT_PATTERN: .finished
        default: .error(try ErrorConverter.convertReturn(consuming: value.raw))
        }
    }
}

protocol FfiBorrowedSliceConstructor {
    associatedtype BorrowedSlice
    associatedtype Element
    static func construct(_ buffer: UnsafeBufferPointer<Element>) -> BorrowedSlice
}

internal class StablePointerArray<Element> {
    internal let buffer: UnsafeMutableBufferPointer<Element>
    internal init(fromContentsOf elements: [Element]) {
        self.buffer = UnsafeMutableBufferPointer.allocate(capacity: elements.count)
        // initialize returns the index at the end of the buffer. We don't need it.
        _ = self.buffer.initialize(fromContentsOf: elements)
    }
    deinit {
        self.buffer.deinitialize()
        self.buffer.deallocate()
    }
}

internal enum ArrayArgConverter<Converter: NiceArgConverter, SliceCons: FfiBorrowedSliceConstructor>: NiceArgConverter
where SliceCons.Element == Converter.FfiArg {
    typealias NiceArg = [Converter.NiceArg]
    typealias FfiArg = SliceCons.BorrowedSlice
    typealias KeepAlive = (StablePointerArray<Converter.FfiArg>, [Converter.KeepAlive])

    private static func convertArgCore(_ arg: [Converter.NiceArg]) -> ([Converter.FfiArg], [Converter.KeepAlive]) {
        var keepAlives: [Converter.KeepAlive] = []
        var contents: [Converter.FfiArg] = []
        contents.reserveCapacity(arg.count)
        // We don't reserve capacity for keepAlives, since we might not add to it for many types
        for item in arg {
            let (ffi, ka) = Converter.convertArg(item)
            contents.append(ffi)
            if let ka = ka {
                keepAlives.append(ka)
            }
        }
        return (contents, keepAlives)
    }

    static func convertArgBorrowed<Result>(
        _ arg: [Converter.NiceArg],
        _ thunk: (FfiArg) throws -> Result
    ) rethrows -> Result {
        let (contents, keepAlives) = convertArgCore(arg)
        return try withExtendedLifetime(keepAlives) {
            try contents.withUnsafeBufferPointer { buf in
                try thunk(SliceCons.construct(buf))
            }
        }
    }

    static func convertArg(_ arg: NiceArg) -> (FfiArg, KeepAlive?) {
        let (contents, keepAlives) = convertArgCore(arg)
        let contentsStable = StablePointerArray(fromContentsOf: contents)
        return (SliceCons.construct(UnsafeBufferPointer(contentsStable.buffer)), (contentsStable, keepAlives))
    }
}

internal protocol FfiOwnedBufferOfMaxAlignedProject {
    associatedtype Buffer
    associatedtype Element
    static func empty() -> Buffer
    static func project(_ buffer: Buffer) -> UnsafeBufferPointer<Element>
    static func typeErased(_ buffer: Buffer) -> SignalOwnedBufferOfMaxAlignedc_void
}

internal enum ArrayReturnConverter<Converter: NiceReturnConverter, BufferProj: FfiOwnedBufferOfMaxAlignedProject>:
    NiceReturnConverter
where BufferProj.Element == Converter.FfiReturn {
    typealias NiceReturn = [Converter.NiceReturn]
    typealias FfiReturn = BufferProj.Buffer

    static func emptyFfiReturn() -> FfiReturn {
        BufferProj.empty()
    }

    static func convertReturn(consuming value: FfiReturn) throws -> NiceReturn {
        defer {
            SignalFfi.signal_free_owned_buffer_of_max_aligned(BufferProj.typeErased(value))
        }
        let buffer = BufferProj.project(value)
        var out: NiceReturn = []
        out.reserveCapacity(buffer.count)
        var err: (any Error)? = nil
        for x in buffer {
            // We want to consume all return values, even if there's an intermediate failure, to
            // avoid leaking memory.
            do {
                out.append(try Converter.convertReturn(consuming: x))
            } catch {
                err = error
            }
        }
        if let err = err {
            throw err
        }
        return out
    }
}

internal struct BackupCdnCredentialsConverter: NiceReturnConverter {
    typealias NiceReturn = BackupCdnCredentials
    typealias FfiReturn = SignalPairOfOwnedBufferOfCStringPtrOwnedBufferOfCStringPtr

    static func emptyFfiReturn() -> FfiReturn {
        .init()
    }
    static func convertReturn(consuming value: FfiReturn) throws -> NiceReturn {
        defer {
            signal_free_list_of_strings(value.first)
            signal_free_list_of_strings(value.second)
        }

        if value.first.length != value.second.length {
            throw SignalError.internalError(
                "BackupCdnCredentials headers do not have the same number of names and values"
            )
        }

        let names = UnsafeBufferPointer(start: value.first.base, count: value.first.length)
        let values = UnsafeBufferPointer(start: value.second.base, count: value.second.length)
        var headers: [String: String] = .init(minimumCapacity: names.count)
        for (nextName, nextValue) in zip(names, values) {
            guard let nextName, let nextValue else {
                throw SignalError.internalError("null pointer in BackupCdnCredentials headers")
            }
            // Note that we don't free the Rust-allocated strings here;
            // signal_free_list_of_strings will take care of that.
            headers[String(cString: nextName)] = String(cString: nextValue)
        }

        return BackupCdnCredentials(headers: headers)
    }
}

// swiftlint:disable:next todo
// TODO: Get to the point where we can make this generic.
internal struct PairOfStringConverterAndStringConverter: NiceReturnConverter {
    typealias NiceReturn = (String, String)
    typealias FfiReturn = SignalPairOfCStringPtrCStringPtr

    static func emptyFfiReturn() -> SignalPairOfCStringPtrCStringPtr {
        .init()
    }
    static func convertReturn(consuming value: SignalPairOfCStringPtrCStringPtr) throws -> (String, String) {
        let first = Result { try StringConverter.convertReturn(consuming: value.first) }
        let second = Result { try StringConverter.convertReturn(consuming: value.second) }
        return (try first.get(), try second.get())
    }
}

internal protocol FixedByteArrayHelper {
    associatedtype Ffi: Sendable
    static func count() -> Int
    static func emptyFfi() -> Ffi
    static func toData(_ ffi: Ffi) -> Data
}
extension FixedByteArrayHelper {
    static func toData(_ ffi: Ffi) -> Data {
        withUnsafeBytes(of: ffi) { Data($0) }
    }
}

internal enum FixedByteArrayConverter<Helper: FixedByteArrayHelper>: NiceArgConverter, NiceReturnConverter {
    static func convertArg(_ arg: Data) -> (FfiArg, KeepAlive?) {
        precondition(arg.count == Helper.count())
        let data = arg as NSData
        return (data.bytes.assumingMemoryBound(to: Helper.Ffi.self), data)
    }

    static func convertArgBorrowed<Result>(
        _ arg: Data,
        _ thunk: (FfiArg) throws -> Result
    ) rethrows -> Result {
        precondition(arg.count == Helper.count())
        return try arg.withUnsafeBytes {
            try thunk($0.assumingMemoryBound(to: Helper.Ffi.self).baseAddress!)
        }
    }

    static func emptyFfiReturn() -> Helper.Ffi {
        Helper.emptyFfi()
    }

    static func convertReturn(consuming value: Helper.Ffi) throws -> Data {
        Helper.toData(value)
    }

    typealias NiceArg = Data
    typealias FfiArg = UnsafePointer<Helper.Ffi>?
    typealias KeepAlive = NSData
    typealias NiceReturn = Data
    typealias FfiReturn = Helper.Ffi
}

internal enum UuidNiceConverter: NiceArgConverter, NiceReturnConverter {
    static func convertArg(_ arg: UUID) -> (SignalUuid, Unit?) {
        (SignalUuid(bytes: arg.uuid), nil)
    }

    static func convertArgBorrowed<Result>(_ arg: UUID, _ thunk: (SignalUuid) throws -> Result) rethrows -> Result {
        try thunk(SignalUuid(bytes: arg.uuid))
    }

    static func emptyFfiReturn() -> SignalUuid {
        SignalUuid()
    }

    static func convertReturn(consuming value: SignalUuid) throws -> UUID {
        UUID(uuid: value.bytes)
    }

    typealias NiceArg = UUID
    typealias FfiArg = SignalUuid
    typealias KeepAlive = Unit
    typealias NiceReturn = UUID
    typealias FfiReturn = SignalUuid
}

internal enum DeviceIdConverter: NiceArgConverter, NiceReturnConverter {
    typealias NiceArg = DeviceId
    typealias FfiArg = UInt8
    typealias KeepAlive = Unit
    typealias NiceReturn = DeviceId
    typealias FfiReturn = UInt8
    static func convertArg(_ arg: NiceArg) -> (FfiArg, KeepAlive?) {
        (arg.uint8Value, nil)
    }
    static func convertArgBorrowed<Result>(_ arg: NiceArg, _ thunk: (FfiArg) throws -> Result) rethrows -> Result {
        try thunk(arg.uint8Value)
    }
    static func emptyFfiReturn() -> FfiReturn {
        0
    }
    static func convertReturn(consuming value: FfiReturn) throws -> NiceReturn {
        guard let out = DeviceId(validating: value) else {
            throw SignalError.internalError("Invalid DeviceId")
        }
        return out
    }
}

internal enum TimestampConverter: NiceArgConverter, NiceReturnConverter {
    static func convertDate(_ arg: Date) -> UInt64 {
        UInt64(arg.timeIntervalSince1970 * 1000.0)
    }

    static func convertArg(_ arg: Date) -> (UInt64, Unit?) {
        (Self.convertDate(arg), nil)
    }

    static func convertArgBorrowed<Result>(_ arg: Date, _ thunk: (UInt64) throws -> Result) rethrows -> Result {
        try thunk(Self.convertDate(arg))
    }

    static func emptyFfiReturn() -> UInt64 {
        0
    }

    static func convertReturn(consuming value: UInt64) throws -> Date {
        Date(timeIntervalSince1970: TimeInterval(value) / 1000.0)
    }

    typealias NiceArg = Date
    typealias FfiArg = UInt64
    typealias KeepAlive = Unit
    typealias NiceReturn = Date
    typealias FfiReturn = UInt64
}
