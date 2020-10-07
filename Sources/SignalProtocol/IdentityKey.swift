import SignalFfi

public struct IdentityKey: Equatable {
    public let publicKey: PublicKey

    public init(publicKey: PublicKey) {
        self.publicKey = publicKey
    }

    public init(bytes: [UInt8]) throws {
        publicKey = try PublicKey(bytes)
    }

    public func serialize() throws -> [UInt8] {
        return try publicKey.serialize()
    }
}

public struct IdentityKeyPair {
    public let publicKey: PublicKey
    public let privateKey: PrivateKey

    private init() throws {
        privateKey = try PrivateKey.generate()
        publicKey = try privateKey.publicKey()
    }

    public static func generate() throws -> IdentityKeyPair {
        return try IdentityKeyPair()
    }

    public init(bytes: [UInt8]) throws {
        var pubkeyPtr: OpaquePointer?
        var privkeyPtr: OpaquePointer?
        try checkError(signal_identitykeypair_deserialize(&pubkeyPtr, &privkeyPtr, bytes, bytes.count))

        publicKey = PublicKey(owned: pubkeyPtr!)
        privateKey = PrivateKey(owned: privkeyPtr!)
    }

    public func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_identitykeypair_serialize($0, $1, publicKey.nativeHandle, privateKey.nativeHandle)
        }
    }

    public var identityKey: IdentityKey {
        return IdentityKey(publicKey: publicKey)
    }
}
