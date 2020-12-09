//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

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

public func signalEncrypt<Bytes: ContiguousBytes>(message: Bytes,
                                                  for address: ProtocolAddress,
                                                  sessionStore: SessionStore,
                                                  identityStore: IdentityKeyStore,
                                                  context: StoreContext) throws -> CiphertextMessage {
    return try message.withUnsafeBytes { messageBytes in
        try context.withOpaquePointer { context in
            try withSessionStore(sessionStore) { ffiSessionStore in
                try withIdentityKeyStore(identityStore) { ffiIdentityStore in
                    try invokeFnReturningCiphertextMessage {
                        signal_encrypt_message($0, messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), messageBytes.count, address.nativeHandle, ffiSessionStore, ffiIdentityStore, context)
                    }
                }
            }
        }
    }
}

public func signalDecrypt(message: SignalMessage,
                          from address: ProtocolAddress,
                          sessionStore: SessionStore,
                          identityStore: IdentityKeyStore,
                          context: StoreContext) throws -> [UInt8] {
    return try context.withOpaquePointer { context in
        try withSessionStore(sessionStore) { ffiSessionStore in
            try withIdentityKeyStore(identityStore) { ffiIdentityStore in
                try invokeFnReturningArray {
                    signal_decrypt_message($0, $1, message.nativeHandle, address.nativeHandle, ffiSessionStore, ffiIdentityStore, context)
                }
            }
        }
    }
}

public func signalDecryptPreKey(message: PreKeySignalMessage,
                                from: ProtocolAddress,
                                sessionStore: SessionStore,
                                identityStore: IdentityKeyStore,
                                preKeyStore: PreKeyStore,
                                signedPreKeyStore: SignedPreKeyStore,
                                context: StoreContext) throws -> [UInt8] {
    return try context.withOpaquePointer { context in
        try withSessionStore(sessionStore) { ffiSessionStore in
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
}

public func processPreKeyBundle(_ bundle: PreKeyBundle,
                                for address: ProtocolAddress,
                                sessionStore: SessionStore,
                                identityStore: IdentityKeyStore,
                                context: StoreContext) throws {
    return try context.withOpaquePointer { context in
        try withSessionStore(sessionStore) { ffiSessionStore in
            try withIdentityKeyStore(identityStore) { ffiIdentityStore in
                try checkError(signal_process_prekey_bundle(bundle.nativeHandle, address.nativeHandle, ffiSessionStore, ffiIdentityStore, context))
            }
        }
    }
}

public func groupEncrypt<Bytes: ContiguousBytes>(groupId: SenderKeyName,
                                                 message: Bytes,
                                                 store: SenderKeyStore,
                                                 context: StoreContext) throws -> [UInt8] {
    return try context.withOpaquePointer { context in
        try message.withUnsafeBytes { messageBytes in
            try withSenderKeyStore(store) { ffiStore in
                try invokeFnReturningArray {
                    signal_group_encrypt_message($0, $1, groupId.nativeHandle, messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), messageBytes.count, ffiStore, context)
                }
            }
        }
    }
}

public func groupDecrypt<Bytes: ContiguousBytes>(groupId: SenderKeyName,
                                                 message: Bytes,
                                                 store: SenderKeyStore,
                                                 context: StoreContext) throws -> [UInt8] {
    return try context.withOpaquePointer { context in
        try message.withUnsafeBytes { messageBytes in
            try withSenderKeyStore(store) { ffiStore in
                try invokeFnReturningArray {
                    signal_group_decrypt_message($0, $1, groupId.nativeHandle, messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), messageBytes.count, ffiStore, context)
                }
            }
        }
    }
}

public func processSenderKeyDistributionMessage(sender: SenderKeyName,
                                                message: SenderKeyDistributionMessage,
                                                store: SenderKeyStore,
                                                context: StoreContext) throws {
    return try context.withOpaquePointer { context in
        try withSenderKeyStore(store) {
            try checkError(signal_process_sender_key_distribution_message(sender.nativeHandle,
                                                                          message.nativeHandle,
                                                                          $0, context))
        }
    }
}
