//
// Copyright 2020 Signal Messenger, LLC
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

    public init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let handle: OpaquePointer? = try bytes.withUnsafeBytes {
            var result: OpaquePointer?
            try checkError(signal_session_record_deserialize(&result, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count))
            return result
        }
        super.init(owned: handle!)
    }

    internal override init(borrowing handle: OpaquePointer?) {
        super.init(borrowing: handle)
    }

    public func serialize() -> [UInt8] {
        return failOnError {
            try invokeFnReturningArray {
                signal_session_record_serialize($0, $1, nativeHandle)
            }
        }
    }

    public var hasCurrentState: Bool {
        var result = false
        failOnError(signal_session_record_has_current_state(&result, nativeHandle))
        return result
    }

    public func archiveCurrentState() {
        failOnError(signal_session_record_archive_current_state(nativeHandle))
    }

    public func remoteRegistrationId() throws -> UInt32 {
        return try invokeFnReturningInteger {
            signal_session_record_get_remote_registration_id($0, nativeHandle)
        }
    }
}
