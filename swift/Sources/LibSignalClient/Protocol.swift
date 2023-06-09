//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public func signalEncrypt<Bytes: ContiguousBytes>(message: Bytes,
                                                  for address: ProtocolAddress,
                                                  sessionStore: SessionStore,
                                                  identityStore: IdentityKeyStore,
                                                  context: StoreContext) throws -> CiphertextMessage {
    return try address.withNativeHandle { addressHandle in
        try message.withUnsafeBorrowedBuffer { messageBuffer in
            try context.withOpaquePointer { context in
                try withSessionStore(sessionStore) { ffiSessionStore in
                    try withIdentityKeyStore(identityStore) { ffiIdentityStore in
                        try invokeFnReturningNativeHandle {
                            signal_encrypt_message($0, messageBuffer, addressHandle, ffiSessionStore, ffiIdentityStore, context)
                        }
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
    return try withNativeHandles(message, address) { messageHandle, addressHandle in
        try context.withOpaquePointer { context in
            try withSessionStore(sessionStore) { ffiSessionStore in
                try withIdentityKeyStore(identityStore) { ffiIdentityStore in
                    try invokeFnReturningArray {
                        signal_decrypt_message($0, messageHandle, addressHandle, ffiSessionStore, ffiIdentityStore, context)
                    }
                }
            }
        }
    }
}

public func signalDecryptPreKey(message: PreKeySignalMessage,
                                from address: ProtocolAddress,
                                sessionStore: SessionStore,
                                identityStore: IdentityKeyStore,
                                preKeyStore: PreKeyStore,
                                signedPreKeyStore: SignedPreKeyStore,
                                kyberPreKeyStore: KyberPreKeyStore,
                                context: StoreContext) throws -> [UInt8] {
    return try withNativeHandles(message, address) { messageHandle, addressHandle in
        try context.withOpaquePointer { context in
            try withSessionStore(sessionStore) { ffiSessionStore in
                try withIdentityKeyStore(identityStore) { ffiIdentityStore in
                    try withPreKeyStore(preKeyStore) { ffiPreKeyStore in
                        try withSignedPreKeyStore(signedPreKeyStore) { ffiSignedPreKeyStore in
                            try withKyberPreKeyStore(kyberPreKeyStore) { ffiKyberPreKeyStore in
                                try invokeFnReturningArray {
                                    signal_decrypt_pre_key_message($0, messageHandle, addressHandle, ffiSessionStore, ffiIdentityStore, ffiPreKeyStore, ffiSignedPreKeyStore, ffiKyberPreKeyStore, context)
                                }
                            }
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
    return try withNativeHandles(bundle, address) { bundleHandle, addressHandle in
        try context.withOpaquePointer { context in
            try withSessionStore(sessionStore) { ffiSessionStore in
                try withIdentityKeyStore(identityStore) { ffiIdentityStore in
                    try checkError(signal_process_prekey_bundle(bundleHandle, addressHandle, ffiSessionStore, ffiIdentityStore, context))
                }
            }
        }
    }
}

public func groupEncrypt<Bytes: ContiguousBytes>(_ message: Bytes,
                                                 from sender: ProtocolAddress,
                                                 distributionId: UUID,
                                                 store: SenderKeyStore,
                                                 context: StoreContext) throws -> CiphertextMessage {
    return try sender.withNativeHandle { senderHandle in
        try context.withOpaquePointer { context in
            try message.withUnsafeBorrowedBuffer { messageBuffer in
                try withUnsafePointer(to: distributionId.uuid) { distributionId in
                    try withSenderKeyStore(store) { ffiStore in
                        try invokeFnReturningNativeHandle {
                            signal_group_encrypt_message($0, senderHandle, distributionId, messageBuffer, ffiStore, context)
                        }
                    }
                }
            }
        }
    }
}

public func groupDecrypt<Bytes: ContiguousBytes>(_ message: Bytes,
                                                 from sender: ProtocolAddress,
                                                 store: SenderKeyStore,
                                                 context: StoreContext) throws -> [UInt8] {
    return try sender.withNativeHandle { senderHandle in
        try context.withOpaquePointer { context in
            try message.withUnsafeBorrowedBuffer { messageBuffer in
                try withSenderKeyStore(store) { ffiStore in
                    try invokeFnReturningArray {
                        signal_group_decrypt_message($0, senderHandle, messageBuffer, ffiStore, context)
                    }
                }
            }
        }
    }
}

public func processSenderKeyDistributionMessage(_ message: SenderKeyDistributionMessage,
                                                from sender: ProtocolAddress,
                                                store: SenderKeyStore,
                                                context: StoreContext) throws {
    return try withNativeHandles(sender, message) { senderHandle, messageHandle in
        try context.withOpaquePointer { context in
            try withSenderKeyStore(store) {
                try checkError(signal_process_sender_key_distribution_message(senderHandle,
                                                                              messageHandle,
                                                                              $0, context))
            }
        }
    }
}
