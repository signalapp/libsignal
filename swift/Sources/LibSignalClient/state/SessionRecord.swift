//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class SessionRecord: ClonableHandleOwner {
    override internal class func destroyNativeHandle(_ handle: OpaquePointer) -> SignalFfiErrorRef? {
        return signal_session_record_destroy(handle)
    }

    override internal class func cloneNativeHandle(_ newHandle: inout OpaquePointer?, currentHandle: OpaquePointer?) -> SignalFfiErrorRef? {
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
        hasCurrentState(now: Date())
    }

    public func hasCurrentState(now: Date) -> Bool {
        var result = false
        self.withNativeHandle { nativeHandle in
            failOnError(signal_session_record_has_usable_sender_chain(&result, nativeHandle, UInt64(now.timeIntervalSince1970 * 1000)))
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
        var result = false
        try withNativeHandles(self, key) { sessionHandle, keyHandle in
            try checkError(signal_session_record_current_ratchet_key_matches(&result, sessionHandle, keyHandle))
        }
        return result
    }
}
