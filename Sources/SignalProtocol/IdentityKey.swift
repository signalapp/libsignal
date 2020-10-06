import SignalFfi

struct IdentityKey: Equatable {
    let publicKey: PublicKey

    init(publicKey: PublicKey) {
        self.publicKey = publicKey
    }

    init(bytes: [UInt8]) throws {
        publicKey = try PublicKey(bytes)
    }

    func serialize() throws -> [UInt8] {
        return try publicKey.serialize()
    }
}


struct IdentityKeyPair {
    let publicKey: PublicKey
    let privateKey: PrivateKey

    private init() throws {
        privateKey = try PrivateKey.generate();
        publicKey = try privateKey.publicKey()
    }

    static func generate() throws -> IdentityKeyPair {
        return try IdentityKeyPair()
    }

    init(bytes: [UInt8]) throws {
        var pubkeyPtr: OpaquePointer?
        var privkeyPtr: OpaquePointer?
        try checkError(signal_identitykeypair_deserialize(&pubkeyPtr, &privkeyPtr, bytes, bytes.count))

        publicKey = PublicKey(owned: pubkeyPtr!)
        privateKey = PrivateKey(owned: privkeyPtr!)
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_identitykeypair_serialize($0, $1, publicKey.nativeHandle, privateKey.nativeHandle)
        }
    }

    var identityKey: IdentityKey {
        return IdentityKey(publicKey: publicKey)
    }
}
