//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class PreKeySignalMessage: NativeHandleOwner<SignalMutPointerPreKeySignalMessage> {
    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerPreKeySignalMessage>) -> SignalFfiErrorRef? {
        return signal_pre_key_signal_message_destroy(handle.pointer)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        var result = SignalMutPointerPreKeySignalMessage()
        try bytes.withUnsafeBorrowedBuffer {
            try checkError(signal_pre_key_signal_message_deserialize(&result, $0))
        }
        self.init(owned: NonNull(result)!)
    }

    public func serialize() throws -> [UInt8] {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningArray {
                signal_pre_key_signal_message_serialize($0, nativeHandle.const())
            }
        }
    }

    public func version() throws -> UInt32 {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningInteger {
                signal_pre_key_signal_message_get_version($0, nativeHandle.const())
            }
        }
    }

    public func registrationId() throws -> UInt32 {
        return try withNativeHandle { nativeHandle in
            try invokeFnReturningInteger {
                signal_pre_key_signal_message_get_registration_id($0, nativeHandle.const())
            }
        }
    }

    public func preKeyId() throws -> UInt32? {
        let id = try withNativeHandle { nativeHandle in
            try invokeFnReturningInteger {
                signal_pre_key_signal_message_get_pre_key_id($0, nativeHandle.const())
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
                    signal_pre_key_signal_message_get_signed_pre_key_id($0, nativeHandle.const())
                }
            }
        }
    }

    public var baseKey: PublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_pre_key_signal_message_get_base_key($0, nativeHandle.const())
                }
            }
        }
    }

    public var identityKey: PublicKey {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_pre_key_signal_message_get_identity_key($0, nativeHandle.const())
                }
            }
        }
    }

    public var signalMessage: SignalMessage {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningNativeHandle {
                    signal_pre_key_signal_message_get_signal_message($0, nativeHandle.const())
                }
            }
        }
    }
}

extension SignalMutPointerPreKeySignalMessage: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerPreKeySignalMessage

    public init(untyped: OpaquePointer?) {
        self.init(raw: untyped)
    }

    public func toOpaque() -> OpaquePointer? {
        self.raw
    }

    public func const() -> Self.ConstPointer {
        Self.ConstPointer(raw: self.raw)
    }
}

extension SignalConstPointerPreKeySignalMessage: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
