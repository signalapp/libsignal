import SignalFfi
import Foundation

class PrivateKey {
    private var handle: OpaquePointer?

    init(_ bytes: [UInt8]) throws {
        try CheckError(signal_privatekey_deserialize(&handle, bytes, bytes.count))
    }

    internal init(raw_ptr: OpaquePointer?) {
        handle = raw_ptr
    }

    static func generate() throws -> PrivateKey {
        var handle: OpaquePointer?
        try CheckError(signal_privatekey_generate(&handle))
        return PrivateKey(raw_ptr: handle)
    }

    deinit {
        signal_privatekey_destroy(handle)
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_privatekey_serialize(handle,b,bl) })
    }

    func generateSignature(message: [UInt8]) throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_privatekey_sign(b,bl,handle,message,message.count) })
    }

    func keyAgreement(other_key: PublicKey) throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_privatekey_agree(b,bl,handle,other_key.nativeHandle()) })
    }

    func getPublicKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey(fn: { (k) in signal_privatekey_get_public_key(k, handle) })
    }

    internal func nativeHandle() -> OpaquePointer? {
        return handle
    }

    internal func leakNativeHandle() -> OpaquePointer? {
        let save = handle
        handle = nil
        return save
    }
}
