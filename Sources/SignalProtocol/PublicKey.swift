import SignalFfi
import Foundation

class PublicKey: ClonableHandleOwner {
    init(_ bytes: [UInt8]) throws {
        var handle: OpaquePointer?
        try CheckError(signal_publickey_deserialize(&handle, bytes, bytes.count))
        super.init(owned: handle!)
    }

    internal override init(owned handle: OpaquePointer) {
        super.init(owned: handle)
    }

    internal override init(unowned handle: OpaquePointer?) {
        super.init(unowned: handle)
    }

    override class func destroyNativeHandle(_ handle: OpaquePointer) {
        signal_publickey_destroy(handle)
    }

    override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_publickey_clone(&newHandle, currentHandle)
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_publickey_serialize(nativeHandle,b,bl) })
    }

    func verifySignature(message: [UInt8], signature: [UInt8]) throws -> Bool {
        var result: Bool = false
        try CheckError(signal_publickey_verify(nativeHandle, &result, message, message.count, signature, signature.count))
        return result
    }

    func compareWith(other_key: PublicKey) -> Int32 {
        var result : Int32 = 0
        try! CheckError(signal_publickey_compare(&result, nativeHandle, other_key.nativeHandle))
        return result
    }
}

extension PublicKey: Equatable {
    static func == (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs.compareWith(other_key: rhs) == 0
    }
}

extension PublicKey: Comparable {
    static func < (lhs: PublicKey, rhs: PublicKey) -> Bool {
        return lhs.compareWith(other_key: rhs) < 0
    }
}
