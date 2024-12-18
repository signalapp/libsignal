//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public enum SizeChoice: Sendable {
    case bytes(UInt32)
    case chunkOf(UInt32)

    fileprivate func sizeInBytes() throws -> UInt32 {
        switch self {
        case .bytes(let n):
            return n
        case .chunkOf(let n):
            return try invokeFnReturningInteger {
                signal_incremental_mac_calculate_chunk_size($0, n)
            }
        }
    }
}

public class IncrementalMacContext: NativeHandleOwner<SignalMutPointerIncrementalMac> {
    private var _digest: Data = .init()

    public private(set) var chunkSizeInBytes: UInt32 = 0

    public convenience init<Key: ContiguousBytes>(key: Key, chunkSize sizeChoice: SizeChoice) throws {
        let chunkSize = try sizeChoice.sizeInBytes()
        let handle = try key.withUnsafeBorrowedBuffer { keyBuffer in
            var macHandle = SignalMutPointerIncrementalMac()
            try checkError(signal_incremental_mac_initialize(&macHandle, keyBuffer, chunkSize))
            return macHandle
        }
        self.init(owned: NonNull(handle)!)
        self.chunkSizeInBytes = chunkSize
    }

    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerIncrementalMac>) -> SignalFfiErrorRef? {
        return signal_incremental_mac_destroy(handle.pointer)
    }

    public func update<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let digest = try bytes.withUnsafeBorrowedBuffer { bytesPtr in
            try withNativeHandle { nativeHandle in
                try invokeFnReturningArray {
                    signal_incremental_mac_update($0, nativeHandle, bytesPtr, 0, UInt32(bytesPtr.length))
                }
            }
        }
        self._digest.append(contentsOf: digest)
    }

    public func finalize() throws -> [UInt8] {
        let digest =
            try withNativeHandle { nativeHandle in
                try invokeFnReturningArray {
                    signal_incremental_mac_finalize($0, nativeHandle)
                }
            }
        self._digest.append(contentsOf: digest)
        return Array(self._digest)
    }
}

extension SignalMutPointerIncrementalMac: SignalMutPointer {
    public typealias ConstPointer = OpaquePointer?

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        nil
    }
}

public class ValidatingMacContext: NativeHandleOwner<SignalMutPointerValidatingMac> {
    public convenience init<
        Key: ContiguousBytes,
        Digest: ContiguousBytes
    >(key: Key, chunkSize sizeChoice: SizeChoice, expectingDigest digest: Digest) throws {
        let chunkSize = try sizeChoice.sizeInBytes()
        let handle = try key.withUnsafeBorrowedBuffer { keyBuffer in
            try digest.withUnsafeBorrowedBuffer { digestBuffer in
                var macHandle = SignalMutPointerValidatingMac()
                try checkError(signal_validating_mac_initialize(&macHandle, keyBuffer, chunkSize, digestBuffer))
                return macHandle
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerValidatingMac>) -> SignalFfiErrorRef? {
        return signal_validating_mac_destroy(handle.pointer)
    }

    public func update<Bytes: ContiguousBytes>(_ bytes: Bytes) throws -> UInt32 {
        let validBytesCount = try bytes.withUnsafeBorrowedBuffer { bytesPtr in
            try withNativeHandle { nativeHandle in
                try invokeFnReturningInteger {
                    signal_validating_mac_update($0, nativeHandle, bytesPtr, 0, UInt32(bytesPtr.length))
                }
            }
        }
        if validBytesCount < 0 {
            throw SignalError.verificationFailed("Bad incremental MAC")
        }
        return UInt32(validBytesCount)
    }

    public func finalize() throws -> UInt32 {
        let validBytesCount =
            try withNativeHandle { nativeHandle in
                try invokeFnReturningInteger {
                    signal_validating_mac_finalize($0, nativeHandle)
                }
            }
        if validBytesCount < 0 {
            throw SignalError.verificationFailed("Bad incremental MAC (finalize)")
        }
        return UInt32(validBytesCount)
    }
}

extension SignalMutPointerValidatingMac: SignalMutPointer {
    public typealias ConstPointer = OpaquePointer?

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        nil
    }
}
