import SignalFfi
import Foundation

class PreKeyBundle {
    private var handle: OpaquePointer?

    deinit {
        signal_pre_key_bundle_destroy(handle)
    }

    internal var nativeHandle: OpaquePointer? {
        return handle
    }

    // with a prekey
    init(registration_id: UInt32,
         device_id: UInt32,
         prekey_id: UInt32,
         prekey: PublicKey,
         signed_prekey_id: UInt32,
         signed_prekey: PublicKey,
         signed_prekey_signature: [UInt8],
         identity_key: IdentityKey) throws {

        // Why is this required??
        var prekey_id = prekey_id
        try CheckError(signal_pre_key_bundle_new(&handle,
                                                 registration_id,
                                                 device_id,
                                                 &prekey_id,
                                                 prekey.nativeHandle,
                                                 signed_prekey_id,
                                                 signed_prekey.nativeHandle,
                                                 signed_prekey_signature,
                                                 signed_prekey_signature.count,
                                                 identity_key.publicKey.nativeHandle))
    }

    // without a prekey
    init(registration_id: UInt32,
         device_id: UInt32,
         signed_prekey_id: UInt32,
         signed_prekey: PublicKey,
         signed_prekey_signature: [UInt8],
         identity_key: IdentityKey) throws {
        try CheckError(signal_pre_key_bundle_new(&handle,
                                                 registration_id,
                                                 device_id,
                                                 nil,
                                                 nil,
                                                 signed_prekey_id,
                                                 signed_prekey.nativeHandle,
                                                 signed_prekey_signature,
                                                 signed_prekey_signature.count,
                                                 identity_key.publicKey.nativeHandle))

    }

    func getRegistrationId() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_pre_key_bundle_get_registration_id(handle, i) })
    }

    func getDeviceId() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_pre_key_bundle_get_device_id(handle, i) })
    }

    func getSignedPreKeyId() throws -> UInt32 {
        return try invokeFnReturningInteger(fn: { (i) in signal_pre_key_bundle_get_signed_pre_key_id(handle, i) })
    }

    func getPreKeyId() throws -> Optional<UInt32> {
        let prekey_id = try invokeFnReturningInteger(fn: { (i) in signal_pre_key_bundle_get_signed_pre_key_id(handle, i) })

        if prekey_id == 0xFFFFFFFF {
            return Optional.none
        } else {
            return Optional.some(prekey_id)
        }
    }

    func getPreKeyPublic() throws -> Optional<PublicKey> {
        return try invokeFnReturningOptionalPublicKey(fn: { (k) in signal_pre_key_bundle_get_pre_key_public(k, handle) })
    }

    func getIdentityKey() throws -> IdentityKey {
        let pk = try invokeFnReturningPublicKey(fn: { (k) in signal_pre_key_bundle_get_identity_key(k, handle) })
        return IdentityKey(pk: pk)
    }

    func getSignedPreKeyPublic() throws -> PublicKey {
        return try invokeFnReturningPublicKey(fn: { (k) in signal_pre_key_bundle_get_signed_pre_key_public(k, handle) })
    }

    func getSignedPreKeySignature() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_pre_key_bundle_get_signed_pre_key_signature(handle,b,bl) })
    }
}
