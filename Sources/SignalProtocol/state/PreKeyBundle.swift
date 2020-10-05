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
    init(registrationId: UInt32,
         deviceId: UInt32,
         prekeyId: UInt32,
         prekey: PublicKey,
         signedPrekeyId: UInt32,
         signedPrekey: PublicKey,
         signedPrekeySignature: [UInt8],
         identity identityKey: IdentityKey) throws {

        // Why is this required??
        var prekey_id = prekeyId
        try checkError(signal_pre_key_bundle_new(&handle,
                                                 registrationId,
                                                 deviceId,
                                                 &prekey_id,
                                                 prekey.nativeHandle,
                                                 signedPrekeyId,
                                                 signedPrekey.nativeHandle,
                                                 signedPrekeySignature,
                                                 signedPrekeySignature.count,
                                                 identityKey.publicKey.nativeHandle))
    }

    // without a prekey
    init(registrationId: UInt32,
         deviceId: UInt32,
         signedPrekeyId: UInt32,
         signedPrekey: PublicKey,
         signedPrekeySignature: [UInt8],
         identity identityKey: IdentityKey) throws {
        try checkError(signal_pre_key_bundle_new(&handle,
                                                 registrationId,
                                                 deviceId,
                                                 nil,
                                                 nil,
                                                 signedPrekeyId,
                                                 signedPrekey.nativeHandle,
                                                 signedPrekeySignature,
                                                 signedPrekeySignature.count,
                                                 identityKey.publicKey.nativeHandle))

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
        return IdentityKey(publicKey: pk)
    }

    func getSignedPreKeyPublic() throws -> PublicKey {
        return try invokeFnReturningPublicKey(fn: { (k) in signal_pre_key_bundle_get_signed_pre_key_public(k, handle) })
    }

    func getSignedPreKeySignature() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_pre_key_bundle_get_signed_pre_key_signature(handle,b,bl) })
    }
}
