import SignalFfi
import Foundation

/*
 SignalFfiError *signal_process_prekey_bundle(PreKeyBundle *bundle,
                                             const ProtocolAddress *protocol_address,
                                             FfiSessionStoreStruct *session_store,
                                             FfiIdentityKeyStoreStruct *identity_key_store,
                                             void *ctx);

SignalFfiError *signal_encrypt_message(const unsigned char **result,
                                       size_t *result_len,
                                       const unsigned char *ptext,
                                       size_t ptext_len,
                                       const ProtocolAddress *protocol_address,
                                       FfiSessionStoreStruct *session_store,
                                       FfiIdentityKeyStoreStruct *identity_key_store,
                                       void *ctx);

SignalFfiError *signal_decrypt_message(const unsigned char **result,
                                       size_t *result_len,
                                       const SignalMessage *message,
                                       const ProtocolAddress *protocol_address,
                                       FfiSessionStoreStruct *session_store,
                                       FfiIdentityKeyStoreStruct *identity_key_store,
                                       void *ctx);

SignalFfiError *signal_decrypt_pre_key_message(const unsigned char **result,
                                               size_t *result_len,
                                               const PreKeySignalMessage *message,
                                               const ProtocolAddress *protocol_address,
                                               FfiSessionStoreStruct *session_store,
                                               FfiIdentityKeyStoreStruct *identity_key_store,
                                               FfiPreKeyStoreStruct *prekey_store,
                                               FfiSignedPreKeyStoreStruct *signed_prekey_store,
                                               void *ctx);

 */

func SignalEncrypt(message: [UInt8],
                   address: ProtocolAddress,
                   session_store: SessionStore,
                   identity_store: IdentityKeyStore,
                   ctx: UnsafeMutableRawPointer?) throws -> [UInt8] {
    var ffi_session = try createFfiSessionStoreStruct(session_store);
    var ffi_identity = try createFfiIdentityKeyStoreStruct(identity_store);
    return try invokeFnReturningArray(fn: { (b,bl) in signal_encrypt_message(b,bl,message,message.count,
                                                                             address.nativeHandle(),
                                                                             &ffi_session, &ffi_identity, ctx) });
}

func SignalDecrypt(message: SignalMessage,
                   address: ProtocolAddress,
                   session_store: SessionStore,
                   identity_store: IdentityKeyStore,
                   ctx: UnsafeMutableRawPointer?) throws -> [UInt8] {
    var ffi_session = try createFfiSessionStoreStruct(session_store);
    var ffi_identity = try createFfiIdentityKeyStoreStruct(identity_store);
    return try invokeFnReturningArray(fn: { (b,bl) in signal_decrypt_message(b,bl,message.nativeHandle(),
                                                                             address.nativeHandle(),
                                                                             &ffi_session, &ffi_identity, ctx) });
}

func SignalDecryptPreKey(message: PreKeySignalMessage,
                         address: ProtocolAddress,
                         session_store: SessionStore,
                         identity_store: IdentityKeyStore,
                         pre_key_store: PreKeyStore,
                         signed_pre_key_store: SignedPreKeyStore,
                         ctx: UnsafeMutableRawPointer?) throws -> [UInt8] {
    var ffi_session = try createFfiSessionStoreStruct(session_store);
    var ffi_identity = try createFfiIdentityKeyStoreStruct(identity_store);
    var ffi_pk = try createFfiPreKeyStoreStruct(pre_key_store);
    var ffi_spk = try createFfiSignedPreKeyStoreStruct(signed_pre_key_store);
    return try invokeFnReturningArray(fn: { (b,bl) in signal_decrypt_pre_key_message(b,bl,message.nativeHandle(),
                                                                                     address.nativeHandle(),
                                                                                     &ffi_session, &ffi_identity,
                                                                                     &ffi_pk, &ffi_spk, ctx) })
}

func ProcessPreKeyBundle(bundle: PreKeyBundle,
                         address: ProtocolAddress,
                         session_store: SessionStore,
                         identity_store: IdentityKeyStore,
                         ctx: UnsafeMutableRawPointer?) throws {
    var ffi_session = try createFfiSessionStoreStruct(session_store);
    var ffi_identity = try createFfiIdentityKeyStoreStruct(identity_store);
    try CheckError(signal_process_prekey_bundle(bundle.nativeHandle(),
                                                address.nativeHandle(),
                                                &ffi_session, &ffi_identity, ctx));
}

func GroupEncrypt(group_id: SenderKeyName,
                  message: [UInt8],
                  store: SenderKeyStore,
                  ctx: UnsafeMutableRawPointer?) throws -> [UInt8] {
    var ffi = try createFfiSenderKeyStoreStruct(store);
    return try invokeFnReturningArray(fn: { (b,bl) in signal_group_encrypt_message(b,bl,group_id.nativeHandle(), message, message.count, &ffi.0, ctx) });
}

func GroupDecrypt(group_id: SenderKeyName,
                  message: [UInt8],
                  store: SenderKeyStore,
                  ctx: UnsafeMutableRawPointer?) throws -> [UInt8] {
    var ffi = try createFfiSenderKeyStoreStruct(store);
    return try invokeFnReturningArray(fn: { (b,bl) in signal_group_decrypt_message(b,bl,group_id.nativeHandle(), message, message.count, &ffi.0, ctx) });
}

func ProcessSenderKeyDistributionMessage(sender_name: SenderKeyName,
                                         msg: SenderKeyDistributionMessage,
                                         store: SenderKeyStore,
                                         ctx: UnsafeMutableRawPointer?) throws {
    var ffi = try createFfiSenderKeyStoreStruct(store);
    try CheckError(signal_process_sender_key_distribution_message(sender_name.nativeHandle(),
                                                                  msg.nativeHandle(),
                                                                  &ffi.0, ctx));
}
