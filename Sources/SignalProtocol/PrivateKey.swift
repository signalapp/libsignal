import SignalFfi

public class PrivateKey: ClonableHandleOwner {
    public init(_ bytes: [UInt8]) throws {
        var handle: OpaquePointer?
        try checkError(signal_privatekey_deserialize(&handle, bytes, bytes.count))
        super.init(owned: handle!)
    }

    internal override init(owned handle: OpaquePointer) {
        super.init(owned: handle)
    }

    public static func generate() throws -> PrivateKey {
        var handle: OpaquePointer?
        try checkError(signal_privatekey_generate(&handle))
        return PrivateKey(owned: handle!)
    }

    internal override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_privatekey_clone(&newHandle, currentHandle)
    }

    internal override class func destroyNativeHandle(_ handle: OpaquePointer) {
        signal_privatekey_destroy(handle)
    }

    public func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_privatekey_serialize(nativeHandle, $0, $1)
        }
    }

    public func generateSignature(message: [UInt8]) throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_privatekey_sign($0, $1, nativeHandle, message, message.count)
        }
    }

    public func keyAgreement(with other: PublicKey) throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_privatekey_agree($0, $1, nativeHandle, other.nativeHandle)
        }
    }

    public func publicKey() throws -> PublicKey {
        return try invokeFnReturningPublicKey {
            signal_privatekey_get_public_key($0, nativeHandle)
        }
    }

}
