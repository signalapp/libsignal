//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import SignalFfi
import Foundation

public class SessionRecord: ClonableHandleOwner {
    internal override class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_session_record_destroy(handle)
    }

    internal override class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
        return signal_session_record_clone(&newHandle, currentHandle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBorrowedBuffer {
            var result: OpaquePointer?
            try checkError(signal_session_record_deserialize(&result, $0))
            return result
        }
        self.init(owned: handle!)
    }

    public func serialize() -> [UInt8] {
        return self.withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_session_record_serialize($0, nativeHandle)
                }
            }
        }
    }

    public var hasCurrentState: Bool {
        var result = false
        self.withNativeHandle { nativeHandle in
            failOnError(signal_session_record_has_current_state(&result, nativeHandle))
        }
        return result
    }

    public func archiveCurrentState() {
        self.withNativeHandle { nativeHandle in
            failOnError(signal_session_record_archive_current_state(nativeHandle))
        }
    }

    public func remoteRegistrationId() throws -> UInt32 {
        return try self.withNativeHandle { nativeHandle in
            try invokeFnReturningInteger {
                signal_session_record_get_remote_registration_id($0, nativeHandle)
            }
        }
    }

    public func currentRatchetKeyMatches(_ key: PublicKey) throws -> Bool {
        var result: Bool = false
        try withNativeHandles(self, key) { sessionHandle, keyHandle in
            try checkError(signal_session_record_current_ratchet_key_matches(&result, sessionHandle, keyHandle))
        }
        return result
    }
}
