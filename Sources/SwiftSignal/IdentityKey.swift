import SignalFfi
import Foundation

class IdentityKey {
    private let key : PublicKey

    init(pk: PublicKey) {
        key = pk
    }

    init(bytes: [UInt8]) throws {
        key = try PublicKey(bytes)
    }

    func serialize() throws -> [UInt8] {
        return try key.serialize()
    }

    func publicKey() -> PublicKey {
        return key
    }
}

extension IdentityKey: Equatable {
    static func == (lhs: IdentityKey, rhs: IdentityKey) -> Bool {
        return lhs.publicKey() == rhs.publicKey()
    }
}


class IdentityKeyPair {
    private let pubkey : PublicKey
    private let privkey : PrivateKey

    init() throws {
        privkey = try PrivateKey.generate();
        pubkey = try privkey.getPublicKey()
    }

    init(bytes: [UInt8]) throws {
        var pubkey_ptr : OpaquePointer?
        var privkey_ptr : OpaquePointer?
        try CheckError(signal_identitykeypair_deserialize(&pubkey_ptr, &privkey_ptr, bytes, bytes.count))

        pubkey = PublicKey(owned: pubkey_ptr!)
        privkey = PrivateKey(owned: privkey_ptr!)
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_identitykeypair_serialize(b,bl,pubkey.nativeHandle(), privkey.nativeHandle()) })
    }

    func publicKey() -> PublicKey {
        return pubkey
    }

    func privateKey() -> PrivateKey {
        return privkey
    }

    func identityKey() -> IdentityKey {
        return IdentityKey(pk: publicKey())
    }
}
