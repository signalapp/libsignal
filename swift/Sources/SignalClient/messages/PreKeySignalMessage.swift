//
// Copyright 2020 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class PreKeySignalMessage {
    private var handle: OpaquePointer?

    deinit {
        failOnError(signal_pre_key_signal_message_destroy(handle))
    }

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        handle = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_pre_key_signal_message_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }
    }

    public func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray {
            signal_pre_key_signal_message_serialize($0, $1, handle)
        }
    }

    public func version() throws -> UInt32 {
        return try invokeFnReturningInteger {
            signal_pre_key_signal_message_get_version($0, handle)
        }
    }

    public func registrationId() throws -> UInt32 {
        return try invokeFnReturningInteger {
            signal_pre_key_signal_message_get_registration_id($0, handle)
        }
    }

    public func preKeyId() throws -> UInt32? {
        let id = try invokeFnReturningInteger {
            signal_pre_key_signal_message_get_pre_key_id($0, handle)
        }

        if id == 0xFFFFFFFF {
            return nil
        } else {
            return id
        }
    }

    public var signedPreKeyId: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_pre_key_signal_message_get_signed_pre_key_id($0, handle)
            }
        }
    }

    public var baseKey: PublicKey {
        return failOnError {
            try invokeFnReturningPublicKey {
                signal_pre_key_signal_message_get_base_key($0, handle)
            }
        }
    }

    public var identityKey: PublicKey {
        return failOnError {
            try invokeFnReturningPublicKey {
                signal_pre_key_signal_message_get_identity_key($0, handle)
            }
        }
    }

    public var signalMessage: SignalMessage {
        var m: OpaquePointer?
        failOnError(signal_pre_key_signal_message_get_signal_message(&m, handle))
        return SignalMessage(owned: m)
    }

    internal var nativeHandle: OpaquePointer? {
        return handle
    }
}
