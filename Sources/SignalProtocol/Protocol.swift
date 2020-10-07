import SignalFfi

/*
 SignalFfiError *signal_process_prekey_bundle(PreKeyBundle *bundle,
                                             const ProtocolAddress *protocol_address,
                                             FfiSessionStoreStruct *session_store,
                                             FfiIdentityKeyStoreStruct *identity_key_store,
                                             void *ctx)

SignalFfiError *signal_encrypt_message(const unsigned char **result,
                                       size_t *result_len,
                                       const unsigned char *ptext,
                                       size_t ptext_len,
                                       const ProtocolAddress *protocol_address,
                                       FfiSessionStoreStruct *session_store,
                                       FfiIdentityKeyStoreStruct *identity_key_store,
                                       void *ctx)

SignalFfiError *signal_decrypt_message(const unsigned char **result,
                                       size_t *result_len,
                                       const SignalMessage *message,
                                       const ProtocolAddress *protocol_address,
                                       FfiSessionStoreStruct *session_store,
                                       FfiIdentityKeyStoreStruct *identity_key_store,
                                       void *ctx)

SignalFfiError *signal_decrypt_pre_key_message(const unsigned char **result,
                                               size_t *result_len,
                                               const PreKeySignalMessage *message,
                                               const ProtocolAddress *protocol_address,
                                               FfiSessionStoreStruct *session_store,
                                               FfiIdentityKeyStoreStruct *identity_key_store,
                                               FfiPreKeyStoreStruct *prekey_store,
                                               FfiSignedPreKeyStoreStruct *signed_prekey_store,
                                               void *ctx)

 */

func signalEncrypt(message: [UInt8],
                   for address: ProtocolAddress,
                   sessionStore: SessionStore,
                   identityStore: IdentityKeyStore,
                   context: UnsafeMutableRawPointer?) throws -> CiphertextMessage {
    return try withSessionStore(sessionStore) { ffiSessionStore in
        try withIdentityKeyStore(identityStore) { ffiIdentityStore in
            try invokeFnReturningCiphertextMessage {
                signal_encrypt_message($0, message, message.count, address.nativeHandle, ffiSessionStore, ffiIdentityStore, context)
            }
        }
    }
}

func signalDecrypt(message: SignalMessage,
                   from address: ProtocolAddress,
                   sessionStore: SessionStore,
                   identityStore: IdentityKeyStore,
                   context: UnsafeMutableRawPointer?) throws -> [UInt8] {
    return try withSessionStore(sessionStore) { ffiSessionStore in
        try withIdentityKeyStore(identityStore) { ffiIdentityStore in
            try invokeFnReturningArray {
                signal_decrypt_message($0, $1, message.nativeHandle, address.nativeHandle, ffiSessionStore, ffiIdentityStore, context)
            }
        }
    }
}

func signalDecryptPreKey(message: PreKeySignalMessage,
                         from: ProtocolAddress,
                         sessionStore: SessionStore,
                         identityStore: IdentityKeyStore,
                         preKeyStore: PreKeyStore,
                         signedPreKeyStore: SignedPreKeyStore,
                         context: UnsafeMutableRawPointer?) throws -> [UInt8] {
    return try withSessionStore(sessionStore) { ffiSessionStore in
        try withIdentityKeyStore(identityStore) { ffiIdentityStore in
            try withPreKeyStore(preKeyStore) { ffiPreKeyStore in
                try withSignedPreKeyStore(signedPreKeyStore) { ffiSignedPreKeyStore in
                    try invokeFnReturningArray {
                        signal_decrypt_pre_key_message($0, $1, message.nativeHandle, from.nativeHandle, ffiSessionStore, ffiIdentityStore, ffiPreKeyStore, ffiSignedPreKeyStore, context)
                    }
                }
            }
        }
    }
}

func processPreKeyBundle(_ bundle: PreKeyBundle,
                         for address: ProtocolAddress,
                         sessionStore: SessionStore,
                         identityStore: IdentityKeyStore,
                         context: UnsafeMutableRawPointer?) throws {
    return try withSessionStore(sessionStore) { ffiSessionStore in
        try withIdentityKeyStore(identityStore) { ffiIdentityStore in
            try checkError(signal_process_prekey_bundle(bundle.nativeHandle, address.nativeHandle, ffiSessionStore, ffiIdentityStore, context))
        }
    }
}

func groupEncrypt(groupId: SenderKeyName,
                  message: [UInt8],
                  store: SenderKeyStore,
                  context: UnsafeMutableRawPointer?) throws -> [UInt8] {
    return try withSenderKeyStore(store) { ffiStore in
        return try invokeFnReturningArray {
            signal_group_encrypt_message($0, $1, groupId.nativeHandle, message, message.count, ffiStore, context)
        }
    }
}

func groupDecrypt(groupId: SenderKeyName,
                  message: [UInt8],
                  store: SenderKeyStore,
                  context: UnsafeMutableRawPointer?) throws -> [UInt8] {
    return try withSenderKeyStore(store) { ffiStore in
        return try invokeFnReturningArray {
            signal_group_decrypt_message($0, $1, groupId.nativeHandle, message, message.count, ffiStore, context)
        }
    }
}

func processSenderKeyDistributionMessage(sender: SenderKeyName,
                                         message: SenderKeyDistributionMessage,
                                         store: SenderKeyStore,
                                         context: UnsafeMutableRawPointer?) throws {
    try withSenderKeyStore(store) {
        try checkError(signal_process_sender_key_distribution_message(sender.nativeHandle,
                                                                      message.nativeHandle,
                                                                      $0, context))
    }
}
