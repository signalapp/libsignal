import SignalFfi
import Foundation

class SenderKeyRecord {
    private var handle: OpaquePointer?;

    deinit {
        signal_sender_key_record_destroy(handle);
    }

    init(bytes: [UInt8]) throws {
        try CheckError(signal_sender_key_record_deserialize(&handle, bytes, bytes.count));
    }

    internal init(raw_ptr: OpaquePointer?) {
        handle = raw_ptr;
    }

    init() throws {
        try CheckError(signal_sender_key_record_new_fresh(&handle));
    }

    func serialize() throws -> [UInt8] {
        return try invokeFnReturningArray(fn: { (b,bl) in signal_sender_key_record_serialize(handle,b,bl) });
    }

    func leakNativeHandle() -> OpaquePointer? {
        let save = handle;
        handle = nil;
        return save;
    }
}
