//
// Copyright 2020-2021 Signal Messenger, LLC.
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
        try message.withUnsafeBytes { messageBytes in
            try context.withOpaquePointer { context in
                try withSessionStore(sessionStore) { ffiSessionStore in
                    try withIdentityKeyStore(identityStore) { ffiIdentityStore in
                        try invokeFnReturningNativeHandle {
                            signal_encrypt_message($0, messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), messageBytes.count, addressHandle, ffiSessionStore, ffiIdentityStore, context)
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
                        signal_decrypt_message($0, $1, messageHandle, addressHandle, ffiSessionStore, ffiIdentityStore, context)
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
                                context: StoreContext) throws -> [UInt8] {
    return try withNativeHandles(message, address) { messageHandle, addressHandle in
        try context.withOpaquePointer { context in
            try withSessionStore(sessionStore) { ffiSessionStore in
                try withIdentityKeyStore(identityStore) { ffiIdentityStore in
                    try withPreKeyStore(preKeyStore) { ffiPreKeyStore in
                        try withSignedPreKeyStore(signedPreKeyStore) { ffiSignedPreKeyStore in
                            try invokeFnReturningArray {
                                signal_decrypt_pre_key_message($0, $1, messageHandle, addressHandle, ffiSessionStore, ffiIdentityStore, ffiPreKeyStore, ffiSignedPreKeyStore, context)
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
            try message.withUnsafeBytes { messageBytes in
                try withUnsafePointer(to: distributionId.uuid) { distributionId in
                    try withSenderKeyStore(store) { ffiStore in
                        try invokeFnReturningNativeHandle {
                            signal_group_encrypt_message($0, senderHandle, distributionId, messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), messageBytes.count, ffiStore, context)
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
            try message.withUnsafeBytes { messageBytes in
                try withSenderKeyStore(store) { ffiStore in
                    try invokeFnReturningArray {
                        signal_group_decrypt_message($0, $1, senderHandle, messageBytes.baseAddress?.assumingMemoryBound(to: UInt8.self), messageBytes.count, ffiStore, context)
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
