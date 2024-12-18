//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class KEMKeyPair: ClonableHandleOwner<SignalMutPointerKyberKeyPair>, @unchecked Sendable {
    public static func generate() -> KEMKeyPair {
        return failOnError {
            try invokeFnReturningNativeHandle {
                signal_kyber_key_pair_generate($0)
            }
        }
    }

    override internal class func cloneNativeHandle(_ newHandle: inout SignalMutPointerKyberKeyPair, currentHandle: SignalConstPointerKyberKeyPair) -> SignalFfiErrorRef? {
        return signal_kyber_key_pair_clone(&newHandle, currentHandle)
    }

    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerKyberKeyPair>) -> SignalFfiErrorRef? {
        return signal_kyber_key_pair_destroy(handle.pointer)
    }

    public var publicKey: KEMPublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_kyber_key_pair_get_public_key($0, nativeHandle.const())
                }
            }
        }
    }

    public var secretKey: KEMSecretKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_kyber_key_pair_get_secret_key($0, nativeHandle.const())
                }
            }
        }
    }
}

extension SignalMutPointerKyberKeyPair: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerKyberKeyPair

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

extension SignalConstPointerKyberKeyPair: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

public class KEMPublicKey: ClonableHandleOwner<SignalMutPointerKyberPublicKey>, @unchecked Sendable {
    public convenience init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle = try bytes.withUnsafeBorrowedBuffer {
            var result = SignalMutPointerKyberPublicKey()
            try checkError(signal_kyber_public_key_deserialize(&result, $0))
            return result
        }
        self.init(owned: NonNull(handle)!)
    }

    override internal class func cloneNativeHandle(_ newHandle: inout SignalMutPointerKyberPublicKey, currentHandle: SignalConstPointerKyberPublicKey) -> SignalFfiErrorRef? {
        return signal_kyber_public_key_clone(&newHandle, currentHandle)
    }

    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerKyberPublicKey>) -> SignalFfiErrorRef? {
        return signal_kyber_public_key_destroy(handle.pointer)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_kyber_public_key_serialize($0, nativeHandle.const())
                }
            }
        }
    }
}

extension SignalMutPointerKyberPublicKey: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerKyberPublicKey

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

extension SignalConstPointerKyberPublicKey: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}

extension KEMPublicKey: Equatable {
    public static func == (lhs: KEMPublicKey, rhs: KEMPublicKey) -> Bool {
        return withNativeHandles(lhs, rhs) { lHandle, rHandle in
            failOnError {
                try invokeFnReturningBool {
                    signal_kyber_public_key_equals($0, lHandle.const(), rHandle.const())
                }
            }
        }
    }
}

public class KEMSecretKey: ClonableHandleOwner<SignalMutPointerKyberSecretKey>, @unchecked Sendable {
    public convenience init<Bytes: ContiguousBytes>(_ bytes: Bytes) throws {
        let handle = try bytes.withUnsafeBorrowedBuffer {
            var result = SignalMutPointerKyberSecretKey()
            try checkError(signal_kyber_secret_key_deserialize(&result, $0))
            return result
        }
        self.init(owned: NonNull(handle)!)
    }

    override internal class func cloneNativeHandle(_ newHandle: inout SignalMutPointerKyberSecretKey, currentHandle: SignalConstPointerKyberSecretKey) -> SignalFfiErrorRef? {
        return signal_kyber_secret_key_clone(&newHandle, currentHandle)
    }

    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerKyberSecretKey>) -> SignalFfiErrorRef? {
        return signal_kyber_secret_key_destroy(handle.pointer)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_kyber_secret_key_serialize($0, nativeHandle.const())
                }
            }
        }
    }
}

extension SignalMutPointerKyberSecretKey: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerKyberSecretKey

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

extension SignalConstPointerKyberSecretKey: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
