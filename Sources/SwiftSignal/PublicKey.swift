import SignalFfi
import Foundation

class PublicKey {
    private var handle: OpaquePointer?

    init(_ bytes: [UInt8]) throws {
        try CheckError(signal_publickey_deserialize(&handle, bytes, bytes.count))
    }

    internal init(raw_ptr: OpaquePointer?) {
        handle = raw_ptr
    }

    internal init(clone_from: OpaquePointer?) throws {
        try CheckError(signal_publickey_clone(&handle, clone_from))
    }

    deinit {
        signal_publickey_destroy(handle)
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_publickey_serialize(handle,b,bl) })
    }

    func verifySignature(message: [UInt8], signature: [UInt8]) throws -> Bool {
        var result : UInt8 = 0
        try CheckError(signal_publickey_verify(handle, &result, message, message.count, signature, signature.count))

        if result == 1 {
            return true
        } else {
            return false
        }
    }

    func compareWith(other_key: PublicKey) throws -> Int32 {
        var result : Int32 = 0
        try CheckError(signal_publickey_compare(&result, handle, other_key.handle))
        return result
    }

    internal func nativeHandle() -> OpaquePointer? {
        return handle
    }

    internal func leakNativeHandle() -> OpaquePointer? {
        let save = handle;
        handle = nil
        return save
    }
}

extension PublicKey: Equatable {
    static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return try! lhs.compareWith(other_key: rhs) == 0
    }
}

extension PublicKey: Comparable {
    static func < (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return try! lhs.compareWith(other_key: rhs) < 0
    }
}
