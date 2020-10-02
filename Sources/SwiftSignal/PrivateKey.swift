import SignalFfi
import Foundation

class PrivateKey: ClonableHandleOwner {
    init(_ bytes: [UInt8]) throws {
        var handle: OpaquePointer?
        try CheckError(signal_privatekey_deserialize(&handle, bytes, bytes.count))
        super.init(owned: handle!)
    }

    override internal init(owned handle: OpaquePointer) {
        super.init(owned: handle)
    }

    static func generate() throws -> PrivateKey {
        var handle: OpaquePointer?
        try CheckError(signal_privatekey_generate(&handle))
        return PrivateKey(owned: handle!)
    }

    override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_privatekey_clone(&newHandle, currentHandle)
    }

    override class func destroyNativeHandle(_ handle: OpaquePointer) {
        signal_privatekey_destroy(handle)
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_privatekey_serialize(nativeHandle(),b,bl) })
    }

    func generateSignature(message: [UInt8]) throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_privatekey_sign(b,bl,nativeHandle(),message,message.count) })
    }

    func keyAgreement(other_key: PublicKey) throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_privatekey_agree(b,bl,nativeHandle(),other_key.nativeHandle()) })
    }

    func getPublicKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey(fn: { (k) in signal_privatekey_get_public_key(k, nativeHandle()) })
    }

}
