//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

import Foundation
import SignalFfi

public class SenderKeyRecord: ClonableHandleOwner<SignalMutPointerSenderKeyRecord> {
    override internal class func destroyNativeHandle(_ handle: NonNull<SignalMutPointerSenderKeyRecord>) -> SignalFfiErrorRef? {
        return signal_sender_key_record_destroy(handle.pointer)
    }

    override internal class func cloneNativeHandle(_ newHandle: inout SignalMutPointerSenderKeyRecord, currentHandle: SignalConstPointerSenderKeyRecord) -> SignalFfiErrorRef? {
        return signal_sender_key_record_clone(&newHandle, currentHandle)
    }

    public convenience init<Bytes: ContiguousBytes>(bytes: Bytes) throws {
        let handle = try bytes.withUnsafeBorrowedBuffer {
            var result = SignalMutPointerSenderKeyRecord()
            try checkError(signal_sender_key_record_deserialize(&result, $0))
            return result
        }
        self.init(owned: NonNull(handle)!)
    }

    public func serialize() -> [UInt8] {
        return withNativeHandle { nativeHandle in
            failOnError {
                try invokeFnReturningArray {
                    signal_sender_key_record_serialize($0, nativeHandle.const())
                }
            }
        }
    }
}

extension SignalMutPointerSenderKeyRecord: SignalMutPointer {
    public typealias ConstPointer = SignalConstPointerSenderKeyRecord

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

extension SignalConstPointerSenderKeyRecord: SignalConstPointer {
    public func toOpaque() -> OpaquePointer? {
        self.raw
    }
}
