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
    typealias FfiArg = UnsafePointer<CChar>
    typealias KeepAlive = NSString
    typealias FfiReturn = UnsafePointer<CChar>?
    typealias NiceReturn = String

    static func convertArg(_ arg: String) -> (UnsafePointer<CChar>, NSString?) {
        let nsstring = arg as NSString
        return (nsstring.utf8String!, nsstring)
    }

    static func convertArgBorrowed<Result>(
        _ arg: String,
        _ thunk: (UnsafePointer<CChar>) throws -> Result
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
