//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class SessionRecord: ClonableHandleOwner<SignalMutPointerSessionRecord> {
    override internal class func destroyNativeHandle(
        _ handle: NonNull<SignalMutPointerSessionRecord>
    ) -> SignalFfiErrorRef? {
        return signal_session_record_destroy(handle.pointer)
    }

    override internal class func cloneNativeHandle(
        _ newHandle: inout SignalMutPointerSessionRecord,
        currentHandle: SignalConstPointerSessionRecord
    ) -> SignalFfiErrorRef? {
        return signal_session_record_clone(&newHandle, currentHandle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let handle = try bytes.withUnsafeBorrowedBuffer { bytes in
            try invokeFnReturningValueByPointer(.init()) {
                signal_session_record_deserialize($0, bytes)
            }
        }
        self.init(owned: NonNull(handle)!)
    }

    public func serialize() -> Data {
        return self.withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningData {
                    signal_session_record_serialize($0, nativeHandle.const())
                }
            }
        }
    }

    public var hasCurrentState: Bool {
        hasCurrentState(now: Date())
    }

    public func hasCurrentState(now: Date) -> Bool {
        return self.withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningBool {
                    signal_session_record_has_usable_sender_chain(
                        $0,
                        nativeHandle.const(),
                        UInt64(now.timeIntervalSince1970 * 1000)
                    )
                }
            }
        }
    }

    public func archiveCurrentState() {
        self.withNativeHandle { nativeHandle in
            failOnError(signal_session_record_archive_current_state(nativeHandle))
        }
    }

    public func remoteRegistrationId() throws -> UInt32 {
        return try self.withNativeHandle { nativeHandle in
            try invokeFnReturningInteger {
                signal_session_record_get_remote_registration_id($0, nativeHandle.const())
            }
        }
    }

    public func currentRatchetKeyMatches(_ key: PublicKey) throws -> Bool {
        return try withAllBorrowed(self, key) { sessionHandle, keyHandle in
            try invokeFnReturningBool {
                signal_session_record_current_ratchet_key_matches($0, sessionHandle.const(), keyHandle.const())
            }
        }
    }
}

extension SignalMutPointerSessionRecord: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerSessionRecord

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

extension SignalConstPointerSessionRecord: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
