//
// Copyright 2020-2021 Signal Messenger, LLC
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class SignalMessage: NativeHandleOwner {
    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_message_destroy(handle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        var result: OpaquePointer?
        try bytes.withUnsafeBytes {
            try checkError(signal_message_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
        }
        self.init(owned: result!)
    }

    public var senderRatchetKey: PublicKey {
        return failOnError {
            try invokeFnReturningNativeHandle {
                signal_message_get_sender_ratchet_key($0, nativeHandle)
            }
        }
    }

    public var body: [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_message_get_body($0, $1, nativeHandle)
            }
        }
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_message_get_serialized($0, $1, nativeHandle)
            }
        }
    }

    public var messageVersion: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_message_get_message_version($0, nativeHandle)
            }
        }
    }

    public var counter: UInt32 {
        return failOnError {
            try invokeFnReturningInteger {
                signal_message_get_counter($0, nativeHandle)
            }
        }
    }

    public func verifyMac<Bytes: ContiguousBytes>(sender: PublicKey,
                                                  receiver: PublicKey,
                                                  macKey: Bytes) throws -> Bool {
        return try macKey.withUnsafeBytes {
            var result: Bool = false
            try checkError(signal_message_verify_mac(&result,
                                                     nativeHandle,
                                                     sender.nativeHandle,
                                                     receiver.nativeHandle,
                                                     $0.baseAddress?.assumingMemoryBound(to: UInt8.self),
                                                     $0.count))
            return result
        }
    }
}
