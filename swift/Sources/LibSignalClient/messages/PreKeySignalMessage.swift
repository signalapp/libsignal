//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class PreKeySignalMessage: NativeHandleOwner {
    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_pre_key_signal_message_destroy(handle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        var result: OpaquePointer?
        try bytes.withUnsafeBorrowedBuffer {
            try checkError(signal_pre_key_signal_message_deserialize(&result, $0))
        }
        self.init(owned: result!)
    }

    public func serialize() throws -> [UInt8] {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningArray {
                signal_pre_key_signal_message_serialize($0, nativeHandle)
            }
        }
    }

    public func version() throws -> UInt32 {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningInteger {
                signal_pre_key_signal_message_get_version($0, nativeHandle)
            }
        }
    }

    public func registrationId() throws -> UInt32 {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningInteger {
                signal_pre_key_signal_message_get_registration_id($0, nativeHandle)
            }
        }
    }

    public func preKeyId() throws -> UInt32? {
        let id = try withNativeHandle { nativeHandle in
            try invokeFnReturningInteger {
                signal_pre_key_signal_message_get_pre_key_id($0, nativeHandle)
            }
        }

        if id == 0xFFFF_FFFF {
            return nil
        } else {
            return id
        }
    }

    public var signedPreKeyId: UInt32 {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningInteger {
                    signal_pre_key_signal_message_get_signed_pre_key_id($0, nativeHandle)
                }
            }
        }
    }

    public var baseKey: PublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_pre_key_signal_message_get_base_key($0, nativeHandle)
                }
            }
        }
    }

    public var identityKey: PublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_pre_key_signal_message_get_identity_key($0, nativeHandle)
                }
            }
        }
    }

    public var signalMessage: SignalMessage {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_pre_key_signal_message_get_signal_message($0, nativeHandle)
                }
            }
        }
    }
}
