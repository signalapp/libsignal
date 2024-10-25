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

public class IncrementalMacContext: NativeHandleOwner {
    private var _digest: Data = .init()

    public private(set) var chunkSizeInBytes: UInt32 = 0

    public convenience init<Key: ContiguousBytes>(key: Key, chunkSize sizeChoice: SizeChoice) throws {
        let chunkSize = try sizeChoice.sizeInBytes()
        let handle: OpaquePointer? = try key.withUnsafeBorrowedBuffer { keyBuffer in
            var macHandle: OpaquePointer?
            try checkError(signal_incremental_mac_initialize(&macHandle, keyBuffer, chunkSize))
            return macHandle
        }
        self.init(owned: handle!)
        self.chunkSizeInBytes = chunkSize
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_incremental_mac_destroy(handle)
    }

    public func update<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let digest = try bytes.withUnsafeBorrowedBuffer { bytesPtr in
            try invokeFnReturningArray {
                signal_incremental_mac_update($0, unsafeNativeHandle, bytesPtr, 0, UInt32(bytesPtr.length))
            }
        }
        self._digest.append(contentsOf: digest)
    }

    public func finalize() throws -> [UInt8] {
        let digest = try invokeFnReturningArray {
            signal_incremental_mac_finalize($0, unsafeNativeHandle)
        }
        self._digest.append(contentsOf: digest)
        return Array(self._digest)
    }
}

public class ValidatingMacContext: NativeHandleOwner {
    public convenience init<
        Key: ContiguousBytes,
        Digest: ContiguousBytes
    >(key: Key, chunkSize sizeChoice: SizeChoice, expectingDigest digest: Digest) throws {
        let chunkSize = try sizeChoice.sizeInBytes()
        let handle: OpaquePointer? = try key.withUnsafeBorrowedBuffer { keyBuffer in
            try digest.withUnsafeBorrowedBuffer { digestBuffer in
                var macHandle: OpaquePointer?
                try checkError(signal_validating_mac_initialize(&macHandle, keyBuffer, chunkSize, digestBuffer))
                return macHandle
            }
        }
        self.init(owned: handle!)
    }

    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_validating_mac_destroy(handle)
    }

    public func update<Bytes: ContiguousBytes>(_ bytes: Bytes) throws -> UInt32 {
        let validBytesCount = try bytes.withUnsafeBorrowedBuffer { bytesPtr in
            try invokeFnReturningInteger {
                signal_validating_mac_update($0, unsafeNativeHandle, bytesPtr, 0, UInt32(bytesPtr.length))
            }
        }
        if validBytesCount < 0 {
            throw SignalError.verificationFailed("Bad incremental MAC")
        }
        return UInt32(validBytesCount)
    }

    public func finalize() throws -> UInt32 {
        let validBytesCount = try invokeFnReturningInteger {
            signal_validating_mac_finalize($0, unsafeNativeHandle)
        }
        if validBytesCount < 0 {
            throw SignalError.verificationFailed("Bad incremental MAC (finalize)")
        }
        return UInt32(validBytesCount)
    }
}
